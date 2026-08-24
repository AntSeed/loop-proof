//! Prints the canonical journal ABI fixture consumed by the monorepo's
//! AntseedWashTradingJournalCompat.t.sol — run with
//! `cargo run -p wash-predicate --example encode_fixture`.

use alloy_primitives::{address, b256};
use wash_predicate::{SubjectRecord, WashJournal};

fn main() {
    let journal = WashJournal {
        predicate_id: wash_predicate::CLOSED_LOOP_PREDICATE_ID,
        chain_id: wash_predicate::BASE_CHAIN_ID,
        period_start_block: wash_predicate::PERIOD_START_BLOCK,
        period_end_block: wash_predicate::PERIOD_END_BLOCK,
        claim_id: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
        subjects: vec![SubjectRecord {
            subject: address!("00000000000000000000000000000000000000aa"),
            wash_volume: 1_200_000_000,
            settled_volume: 2_400_000_000,
        }],
        block_refs: vec![
            (
                wash_predicate::PERIOD_LEDGER_START_BLOCK,
                b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            ),
            (
                wash_predicate::PERIOD_END_BLOCK,
                b256!("3333333333333333333333333333333333333333333333333333333333333333"),
            ),
        ],
    };
    println!("0x{}", alloy_primitives::hex::encode(journal.abi_encode()));
}
