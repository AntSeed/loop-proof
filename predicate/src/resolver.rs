//! Resolution of `(block, receipt, log)` / `(block, transaction)` references
//! into authenticated, decoded evidence, plus bound storage reads.

use crate::{
    EvidenceBlock, LogRef, ReceiptRef, StateRead, TransactionRef, CHANNELS_ADDRESS,
    DEPOSITS_ADDRESS, USDC_ADDRESS,
};
use alloy_consensus::{transaction::SignerRecoverable, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, U256};
use loop_core::{
    receipt_log, receipt_success, ParsedLog, ReceiptProof, CHANNEL_SETTLED_TOPIC, DEPOSITED_TOPIC,
    TRANSFER_TOPIC,
};

/// A totally ordered on-chain position for one log — used both for duplicate
/// rejection and for event ordering.
pub type LogKey = (u64, u64, usize);

pub struct ChainResolver<'a> {
    pub blocks: &'a [EvidenceBlock],
}

impl ChainResolver<'_> {
    pub fn block(&self, index: usize) -> Result<&EvidenceBlock, String> {
        self.blocks
            .get(index)
            .ok_or("block reference out of range".into())
    }

    pub fn receipt(
        &self,
        reference: ReceiptRef,
    ) -> Result<(&ReceiptProof, &EvidenceBlock), String> {
        let block = self.block(reference.block)?;
        Ok((
            block
                .receipts
                .get(reference.receipt)
                .ok_or("receipt reference out of range")?,
            block,
        ))
    }

    /// Resolve a log from a successful receipt.
    pub fn log(
        &self,
        reference: LogRef,
    ) -> Result<(ParsedLog, &ReceiptProof, &EvidenceBlock), String> {
        let (receipt, block) = self.receipt(ReceiptRef {
            block: reference.block,
            receipt: reference.receipt,
        })?;
        if !receipt_success(&receipt.value)? {
            return Err("referenced receipt reverted".into());
        }
        Ok((receipt_log(&receipt.value, reference.log)?, receipt, block))
    }

    pub fn log_key(&self, reference: LogRef) -> Result<LogKey, String> {
        let (_, receipt, block) = self.log(reference)?;
        Ok((block.header.number, receipt.tx_index, reference.log))
    }

    pub fn timestamp(&self, reference: LogRef) -> Result<u64, String> {
        Ok(self.block(reference.block)?.header.timestamp)
    }

    pub fn transaction(
        &self,
        reference: TransactionRef,
    ) -> Result<(&loop_core::TransactionProof, &EvidenceBlock), String> {
        let block = self.block(reference.block)?;
        Ok((
            block
                .transactions
                .get(reference.transaction)
                .ok_or("transaction reference out of range")?,
            block,
        ))
    }

    /// The authenticated transaction that produced a referenced log's receipt.
    pub fn transaction_for_log(&self, reference: LogRef) -> Result<TransactionRef, String> {
        let (_, receipt, block) = self.log(reference)?;
        let mut matches = block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, transaction)| transaction.tx_index == receipt.tx_index);
        let (position, _) = matches
            .next()
            .ok_or("authenticated transaction missing for receipt")?;
        if matches.next().is_some() {
            return Err("duplicate authenticated transaction for receipt".into());
        }
        Ok(TransactionRef {
            block: reference.block,
            transaction: position,
        })
    }

    pub fn decoded_transaction(
        &self,
        reference: TransactionRef,
    ) -> Result<(TxEnvelope, Address, &EvidenceBlock), String> {
        let (proof, block) = self.transaction(reference)?;
        let mut bytes = proof.value.as_ref();
        let envelope = TxEnvelope::decode_2718(&mut bytes)
            .map_err(|error| format!("transaction decode: {error}"))?;
        if !bytes.is_empty() {
            return Err("transaction has trailing bytes".into());
        }
        let signer = envelope
            .recover_signer()
            .map_err(|_| "transaction signer recovery failed")?;
        Ok((envelope, signer, block))
    }

    /// Attribution: the transaction behind `reference` must be signed by
    /// `expected` — never inferred from log topics.
    pub fn require_signer(&self, expected: Address, reference: LogRef) -> Result<(), String> {
        let transaction = self.transaction_for_log(reference)?;
        let (_, signer, _) = self.decoded_transaction(transaction)?;
        if signer != expected {
            return Err("transaction signer mismatch".into());
        }
        Ok(())
    }

    /// USDC `Transfer` log → (from, to, amount, block_number).
    pub fn usdc_transfer(
        &self,
        reference: LogRef,
    ) -> Result<(Address, Address, u128, u64), String> {
        let (log, _, block) = self.log(reference)?;
        if log.address != USDC_ADDRESS
            || log.topics.len() != 3
            || log.topics[0] != TRANSFER_TOPIC
            || log.data.len() != 32
        {
            return Err("not a USDC transfer".into());
        }
        Ok((
            crate::topic_address(log.topics[1]),
            crate::topic_address(log.topics[2]),
            u128::try_from(U256::from_be_slice(&log.data)).map_err(|_| "USDC amount overflow")?,
            block.header.number,
        ))
    }

    /// `ChannelSettled` log → (channel_id, buyer, seller, delta, block_number).
    pub fn settlement(
        &self,
        reference: LogRef,
    ) -> Result<(B256, Address, Address, u128, u64), String> {
        let (log, _, block) = self.log(reference)?;
        if log.address != CHANNELS_ADDRESS
            || log.topics.len() != 4
            || log.topics[0] != CHANNEL_SETTLED_TOPIC
            || log.data.len() < 64
        {
            return Err("not a ChannelSettled event".into());
        }
        Ok((
            log.topics[1],
            crate::topic_address(log.topics[2]),
            crate::topic_address(log.topics[3]),
            u128::try_from(U256::from_be_slice(&log.data[32..64]))
                .map_err(|_| "settlement amount overflow")?,
            block.header.number,
        ))
    }

    /// `Deposited` log on the Deposits contract → (buyer, amount, block_number).
    pub fn protocol_deposit(&self, reference: LogRef) -> Result<(Address, u128, u64), String> {
        let (log, _, block) = self.log(reference)?;
        if log.address != DEPOSITS_ADDRESS
            || log.topics.len() != 2
            || log.topics[0] != DEPOSITED_TOPIC
            || log.data.len() != 32
        {
            return Err("not an Antseed Deposited event".into());
        }
        Ok((
            crate::topic_address(log.topics[1]),
            u128::try_from(U256::from_be_slice(&log.data))
                .map_err(|_| "deposit amount overflow")?,
            block.header.number,
        ))
    }

    /// Verify a bound storage read: the slot is derived by the caller from
    /// pinned layout constants, and the block must be the expected boundary.
    pub fn storage_value(
        &self,
        read: &StateRead,
        expected_block: u64,
        contract: Address,
        slot: B256,
    ) -> Result<U256, String> {
        let block = self.block(read.block)?;
        if block.header.number != expected_block {
            return Err(format!(
                "state read at block {} but the rule requires block {expected_block}",
                block.header.number
            ));
        }
        loop_core::verify_storage_value(block.header.state_root, contract, slot, &read.proof)
    }
}
