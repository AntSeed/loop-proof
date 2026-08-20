use alloy_primitives::{keccak256, Address, B256, U256};
use anyhow::{bail, Context, Result};
use enforcement_core::{
    ChannelDelta, CoordinatedControlInput, CounterDelta, CounterKind, Eip1186AccountProof,
    EnforcementBlock, FunderAuthentication, FunderCohort, FundingEvidence, FundingKind, ReceiptRef,
    StateValueRef, TransactionRef, BASE_CHAIN_ID, CHANNELS_ADDRESS, DEPOSITS_ADDRESS, MAX_BUYERS,
    MAX_EMISSIONS_EPOCH, MINIMUM_NATIVE_FUNDING_WEI, MINIMUM_VOLUME_RAW, NEW_EMISSIONS_ADDRESS,
    OLD_EMISSIONS_ADDRESS, PERIOD_END_BLOCK_EXCLUSIVE, PERIOD_START_BLOCK, PREDICATE_VERSION,
    STATE_END_BLOCK, STATE_START_BLOCK,
};
use loop_host::rpc::Client;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

const STATE_PROOF_CHUNK_SIZE: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SellerDocument {
    network_signals: NetworkSignals,
    strongest_cohort: Option<StrongestCohort>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StrongestCohort {
    funder: Address,
    buyers: Vec<Address>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkSignals {
    native_funder_cohorts: Vec<NativeFunderCohort>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeFunderCohort {
    funder: Address,
    buyer_addresses: Vec<Address>,
}

#[derive(Debug, Deserialize)]
struct NativeFundingFile {
    records: Vec<NativeFundingRecord>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeFundingRecord {
    buyer: Address,
    from: Address,
    amount_wei: String,
    timestamp: u64,
    tx_hash: B256,
}

#[derive(Debug, Deserialize)]
struct ProtocolFundingFile {
    records: Vec<ProtocolFundingRecord>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtocolFundingRecord {
    buyer: Address,
    funder: Address,
    amount_raw: String,
    timestamp: u64,
    tx_hash: B256,
}

#[derive(Clone, Debug)]
enum FundingRecord {
    Native(NativeFundingRecord),
    Protocol(ProtocolFundingRecord),
}

impl FundingRecord {
    fn buyer(&self) -> Address {
        match self {
            Self::Native(record) => record.buyer,
            Self::Protocol(record) => record.buyer,
        }
    }

    fn timestamp(&self) -> u64 {
        match self {
            Self::Native(record) => record.timestamp,
            Self::Protocol(record) => record.timestamp,
        }
    }

    fn transaction_hash(&self) -> B256 {
        match self {
            Self::Native(record) => record.tx_hash,
            Self::Protocol(record) => record.tx_hash,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SettlementPage {
    items: Vec<SettlementRow>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettlementRow {
    channel_id: B256,
    buyer: Address,
    seller: Address,
    delta_usdc: String,
    block_number: u64,
}

#[derive(Clone, Debug)]
struct SelectedChannel {
    channel_id: B256,
    buyer: Address,
    scan_volume: u128,
}

#[derive(Clone, Debug)]
struct LocatedFunding {
    cohort_funder: Address,
    record: FundingRecord,
    block_number: u64,
    transaction_index: u64,
    protocol_logs: Option<(usize, usize)>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WitnessPackage<'a> {
    version: u32,
    kind: &'static str,
    enforceable: bool,
    proof_type: &'static str,
    input: &'a CoordinatedControlInput,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = env::args().skip(1).collect::<Vec<_>>();
    let scan_dir = PathBuf::from(arg(&args, "--scan-dir").context("missing --scan-dir")?);
    let seller = arg(&args, "--seller")
        .context("missing --seller")?
        .parse::<Address>()
        .context("invalid seller address")?;
    let output = PathBuf::from(arg(&args, "--output").context("missing --output")?);
    let requested_funders = optional_arg(&args, "--funders")
        .map(parse_addresses)
        .transpose()?;
    let client = Client::new(primary_rpc_endpoints()?);
    let proof_client = Client::new(proof_rpc_endpoints()?);
    proof_client
        .state_proof(0, STATE_START_BLOCK, CHANNELS_ADDRESS, &[])
        .context("archive RPC preflight failed at the fixed state-start block")?;

    let seller_path = scan_dir
        .join("sellers")
        .join(format!("{seller}.json").to_lowercase());
    let seller_document: SellerDocument = serde_json::from_slice(
        &fs::read(&seller_path).with_context(|| format!("read {}", seller_path.display()))?,
    )
    .with_context(|| format!("decode {}", seller_path.display()))?;
    let funding_path = scan_dir.join("raw/first-native-funding.json");
    let funding_file: NativeFundingFile = serde_json::from_slice(
        &fs::read(&funding_path).with_context(|| format!("read {}", funding_path.display()))?,
    )?;
    let protocol_funding_path = scan_dir.join("raw/protocol-deposits.json");
    let protocol_funding_file: ProtocolFundingFile = serde_json::from_slice(
        &fs::read(&protocol_funding_path)
            .with_context(|| format!("read {}", protocol_funding_path.display()))?,
    )?;

    let assignments = funding_assignments(
        &seller_document.network_signals.native_funder_cohorts,
        seller_document.strongest_cohort.as_ref(),
        &funding_file.records,
        &protocol_funding_file.records,
        requested_funders.as_ref(),
    )?;
    let settlement_path = scan_dir.join("raw/antscan/settlementVolumes.ndjson");
    let (seller_volume, channels) = scan_channels(&settlement_path, seller, &assignments)?;
    let threshold = seller_volume
        .checked_add(1)
        .context("seller volume overflow")?
        / 2;
    let threshold = threshold.max(MINIMUM_VOLUME_RAW);
    let (selected_buyers, selected_channels, selected_volume) =
        select_threshold_witness(&channels, &assignments, threshold)?;
    if selected_buyers.len() > MAX_BUYERS {
        bail!("selected buyer count exceeds predicate cap");
    }

    eprintln!(
        "selected {} buyers, {} channels, {:.6} USDC of {:.6} seller-period USDC",
        selected_buyers.len(),
        selected_channels.len(),
        selected_volume as f64 / 1_000_000.0,
        seller_volume as f64 / 1_000_000.0
    );

    let located_fundings = locate_fundings(&client, &selected_buyers, &assignments)?;
    let (blocks, block_positions, receipt_positions, transaction_positions) =
        materialize_blocks(&client, &located_fundings)?;
    let mut state_proofs = Vec::new();

    let deposits_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_END_BLOCK,
        DEPOSITS_ADDRESS,
        &selected_buyers
            .iter()
            .map(|buyer| enforcement_core::first_channel_slot(*buyer))
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::msg)?,
    )?;

    let start_channel_slots = selected_channels
        .iter()
        .map(|channel| add_slot(enforcement_core::channel_base_slot(channel.channel_id), 2))
        .collect::<Result<Vec<_>>>()?;
    let end_channel_slots = selected_channels
        .iter()
        .flat_map(|channel| {
            let base = enforcement_core::channel_base_slot(channel.channel_id);
            [Ok(base), add_slot(base, 1), add_slot(base, 2)]
        })
        .collect::<Result<Vec<_>>>()?;
    let start_channels_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_START_BLOCK,
        CHANNELS_ADDRESS,
        &start_channel_slots,
    )?;
    let end_channels_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_END_BLOCK,
        CHANNELS_ADDRESS,
        &end_channel_slots,
    )?;

    let old_slots = counter_slots(seller, &selected_buyers, OLD_EMISSIONS_ADDRESS)?;
    let new_slots = counter_slots(seller, &selected_buyers, NEW_EMISSIONS_ADDRESS)?;
    let old_start_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_START_BLOCK,
        OLD_EMISSIONS_ADDRESS,
        &old_slots,
    )?;
    let old_end_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_END_BLOCK,
        OLD_EMISSIONS_ADDRESS,
        &old_slots,
    )?;
    let new_start_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_START_BLOCK,
        NEW_EMISSIONS_ADDRESS,
        &new_slots,
    )?;
    let new_end_account = push_state_proof(
        &proof_client,
        &blocks,
        &block_positions,
        &mut state_proofs,
        STATE_END_BLOCK,
        NEW_EMISSIONS_ADDRESS,
        &new_slots,
    )?;

    let funding_account_indices = materialize_funder_accounts(
        &proof_client,
        &blocks,
        &block_positions,
        &located_fundings,
        &mut state_proofs,
    )?;
    let funding_cohorts = build_funding_cohorts(
        &selected_buyers,
        &assignments,
        &located_fundings,
        &block_positions,
        &receipt_positions,
        &transaction_positions,
        &funding_account_indices,
        deposits_account,
        &state_proofs,
        &proof_client,
    )?;

    let channels = selected_channels
        .iter()
        .map(|channel| {
            let base = enforcement_core::channel_base_slot(channel.channel_id);
            Ok(ChannelDelta {
                channel_id: channel.channel_id,
                buyer: channel.buyer,
                seller,
                start_packed_amounts: state_ref(
                    start_channels_account,
                    add_slot(base, 2)?,
                    &state_proofs,
                )?,
                end_buyer: state_ref(end_channels_account, base, &state_proofs)?,
                end_seller: state_ref(end_channels_account, add_slot(base, 1)?, &state_proofs)?,
                end_packed_amounts: state_ref(
                    end_channels_account,
                    add_slot(base, 2)?,
                    &state_proofs,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let seller_counters = build_counters(
        CounterKind::Seller,
        &[seller],
        old_start_account,
        old_end_account,
        new_start_account,
        new_end_account,
        &state_proofs,
    )?;
    let buyer_counters = build_counters(
        CounterKind::Buyer,
        &selected_buyers,
        old_start_account,
        old_end_account,
        new_start_account,
        new_end_account,
        &state_proofs,
    )?;

    let input = CoordinatedControlInput {
        chain_id: BASE_CHAIN_ID,
        seller,
        funding_cohorts,
        blocks,
        state_proofs,
        channels,
        seller_counters,
        buyer_counters,
    };
    let journal =
        enforcement_core::verify_coordinated_control(&input).map_err(anyhow::Error::msg)?;
    eprintln!(
        "native verification passed: claim {}, qualified {:.6} USDC, seller period {:.6} USDC",
        journal.claim_id,
        journal.qualified_cohort_volume_raw as f64 / 1_000_000.0,
        journal.seller_period_volume_raw as f64 / 1_000_000.0
    );

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let package = WitnessPackage {
        version: PREDICATE_VERSION,
        kind: "antseed-wash-trading-proof-witness",
        enforceable: true,
        proof_type: "P1_COORDINATED_CONTROL",
        input: &input,
    };
    fs::write(&output, format!("{}\n", serde_json::to_string(&package)?))?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn funding_assignments(
    cohorts: &[NativeFunderCohort],
    strongest_cohort: Option<&StrongestCohort>,
    native_records: &[NativeFundingRecord],
    protocol_records: &[ProtocolFundingRecord],
    requested_funders: Option<&Vec<Address>>,
) -> Result<BTreeMap<Address, (Address, FundingRecord)>> {
    let requested = requested_funders.map(|values| values.iter().copied().collect::<BTreeSet<_>>());
    let native_records = native_records
        .iter()
        .filter_map(|record| {
            record
                .amount_wei
                .parse::<u128>()
                .ok()
                .filter(|amount| *amount >= MINIMUM_NATIVE_FUNDING_WEI)
                .map(|_| ((record.from, record.buyer), record.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut protocol_records_by_subject =
        BTreeMap::<(Address, Address), ProtocolFundingRecord>::new();
    for record in protocol_records {
        if record
            .amount_raw
            .parse::<u128>()
            .ok()
            .is_none_or(|amount| amount < 1_000_000)
        {
            continue;
        }
        let key = (record.funder, record.buyer);
        if protocol_records_by_subject
            .get(&key)
            .is_none_or(|existing| record.timestamp < existing.timestamp)
        {
            protocol_records_by_subject.insert(key, record.clone());
        }
    }
    let mut candidates = BTreeMap::<Address, Vec<(Address, FundingRecord)>>::new();
    for cohort in cohorts {
        if cohort.buyer_addresses.len() < 3 {
            continue;
        }
        if requested
            .as_ref()
            .is_some_and(|funders| !funders.contains(&cohort.funder))
        {
            continue;
        }
        for buyer in &cohort.buyer_addresses {
            if let Some(record) = native_records.get(&(cohort.funder, *buyer)) {
                candidates
                    .entry(*buyer)
                    .or_default()
                    .push((cohort.funder, FundingRecord::Native(record.clone())));
            }
        }
    }
    if let Some(cohort) = strongest_cohort.filter(|cohort| cohort.buyers.len() >= 3) {
        if requested
            .as_ref()
            .is_none_or(|funders| funders.contains(&cohort.funder))
        {
            for buyer in &cohort.buyers {
                if let Some(record) = protocol_records_by_subject.get(&(cohort.funder, *buyer)) {
                    candidates
                        .entry(*buyer)
                        .or_default()
                        .push((cohort.funder, FundingRecord::Protocol(record.clone())));
                }
            }
        }
    }
    let tentative = candidates
        .into_iter()
        .map(|(buyer, mut choices)| {
            choices.sort_unstable_by_key(|choice| (choice.1.timestamp(), choice.0));
            (buyer, choices.remove(0))
        })
        .collect::<BTreeMap<_, _>>();
    let mut counts = BTreeMap::<Address, usize>::new();
    for (funder, _) in tentative.values() {
        *counts.entry(*funder).or_default() += 1;
    }
    let assignments = tentative
        .into_iter()
        .filter(|(_, (funder, _))| counts.get(funder).copied().unwrap_or_default() >= 3)
        .collect::<BTreeMap<_, _>>();
    if assignments.len() < 3 {
        bail!("fewer than three buyers have a qualifying exact-funder cohort");
    }
    Ok(assignments)
}

fn scan_channels(
    path: &Path,
    seller: Address,
    assignments: &BTreeMap<Address, (Address, FundingRecord)>,
) -> Result<(u128, Vec<SelectedChannel>)> {
    let reader =
        BufReader::new(File::open(path).with_context(|| format!("read {}", path.display()))?);
    let mut seller_volume = 0u128;
    let mut channels = BTreeMap::<B256, SelectedChannel>::new();
    for line in reader.lines() {
        let page: SettlementPage = serde_json::from_str(&line?)?;
        for row in page.items {
            if row.seller != seller
                || !(PERIOD_START_BLOCK..PERIOD_END_BLOCK_EXCLUSIVE).contains(&row.block_number)
            {
                continue;
            }
            let amount = row.delta_usdc.parse::<u128>()?;
            seller_volume = seller_volume
                .checked_add(amount)
                .context("seller volume overflow")?;
            if !assignments.contains_key(&row.buyer) {
                continue;
            }
            let channel = channels.entry(row.channel_id).or_insert(SelectedChannel {
                channel_id: row.channel_id,
                buyer: row.buyer,
                scan_volume: 0,
            });
            if channel.buyer != row.buyer {
                bail!("scan channel has multiple buyers");
            }
            channel.scan_volume = channel
                .scan_volume
                .checked_add(amount)
                .context("channel volume overflow")?;
        }
    }
    Ok((seller_volume, channels.into_values().collect()))
}

fn select_threshold_witness(
    channels: &[SelectedChannel],
    assignments: &BTreeMap<Address, (Address, FundingRecord)>,
    threshold: u128,
) -> Result<(Vec<Address>, Vec<SelectedChannel>, u128)> {
    let mut by_buyer = BTreeMap::<Address, Vec<SelectedChannel>>::new();
    for channel in channels {
        by_buyer
            .entry(channel.buyer)
            .or_default()
            .push(channel.clone());
    }
    let buyer_volumes = by_buyer
        .iter()
        .map(|(buyer, channels)| {
            (
                *buyer,
                channels
                    .iter()
                    .map(|channel| channel.scan_volume)
                    .sum::<u128>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut funder_buyers = BTreeMap::<Address, Vec<(u128, Address)>>::new();
    for (buyer, volume) in &buyer_volumes {
        let funder = assignments
            .get(buyer)
            .context("buyer funding assignment missing during selection")?
            .0;
        funder_buyers
            .entry(funder)
            .or_default()
            .push((*volume, *buyer));
    }
    let mut funder_groups = funder_buyers
        .into_iter()
        .filter_map(|(funder, mut buyers)| {
            if buyers.len() < 3 {
                return None;
            }
            buyers.sort_unstable_by_key(|(volume, buyer)| (Reverse(*volume), *buyer));
            let volume = buyers.iter().map(|(volume, _)| *volume).sum::<u128>();
            Some((volume, funder, buyers))
        })
        .collect::<Vec<_>>();
    funder_groups.sort_unstable_by_key(|(volume, funder, _)| (Reverse(*volume), *funder));
    let mut selected_buyers = Vec::new();
    let mut available = 0u128;
    for (_, _, buyers) in funder_groups {
        if available >= threshold {
            break;
        }
        for (index, (volume, buyer)) in buyers.into_iter().enumerate() {
            if index >= 3 && available >= threshold {
                break;
            }
            selected_buyers.push(buyer);
            available = available
                .checked_add(volume)
                .context("buyer volume overflow")?;
        }
    }
    if selected_buyers.len() < 3 || available < threshold {
        bail!("qualifying exact-funder cohorts do not reach the P1 threshold");
    }
    selected_buyers.sort_unstable();

    let selected_set = selected_buyers.iter().copied().collect::<BTreeSet<_>>();
    let mut candidates = channels
        .iter()
        .filter(|channel| selected_set.contains(&channel.buyer))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|channel| (Reverse(channel.scan_volume), channel.channel_id));
    let mut selected = BTreeMap::<B256, SelectedChannel>::new();
    for buyer in &selected_buyers {
        let channel = candidates
            .iter()
            .filter(|channel| channel.buyer == *buyer)
            .max_by_key(|channel| (channel.scan_volume, Reverse(channel.channel_id)))
            .context("selected buyer has no channel")?;
        selected.insert(channel.channel_id, channel.clone());
    }
    let mut volume = selected
        .values()
        .map(|channel| channel.scan_volume)
        .sum::<u128>();
    for channel in candidates {
        if volume >= threshold {
            break;
        }
        if selected.contains_key(&channel.channel_id) {
            continue;
        }
        volume = volume
            .checked_add(channel.scan_volume)
            .context("selected channel volume overflow")?;
        selected.insert(channel.channel_id, channel);
    }
    if volume < threshold {
        bail!("selected channels do not reach the P1 threshold");
    }
    Ok((selected_buyers, selected.into_values().collect(), volume))
}

fn locate_fundings(
    client: &Client,
    buyers: &[Address],
    assignments: &BTreeMap<Address, (Address, FundingRecord)>,
) -> Result<Vec<LocatedFunding>> {
    buyers
        .iter()
        .map(|buyer| {
            let (funder, record) = assignments
                .get(buyer)
                .context("buyer funding assignment missing")?;
            let (block_number, transaction_index, protocol_logs) = match record {
                FundingRecord::Native(_) => {
                    let (block, transaction) =
                        client.transaction_location(record.transaction_hash())?;
                    (block, transaction, None)
                }
                FundingRecord::Protocol(protocol) => {
                    let amount = protocol.amount_raw.parse::<u128>()?;
                    let (block, transaction, transfer, deposited) = client
                        .find_protocol_deposit_in_tx(
                            protocol.tx_hash,
                            protocol.funder,
                            protocol.buyer,
                            amount,
                        )?;
                    (block, transaction, Some((transfer, deposited)))
                }
            };
            Ok(LocatedFunding {
                cohort_funder: *funder,
                record: record.clone(),
                block_number,
                transaction_index,
                protocol_logs,
            })
        })
        .collect()
}

type PositionMap = BTreeMap<(u64, u64), usize>;

fn materialize_blocks(
    client: &Client,
    fundings: &[LocatedFunding],
) -> Result<(
    Vec<EnforcementBlock>,
    BTreeMap<u64, usize>,
    PositionMap,
    PositionMap,
)> {
    let mut targets = BTreeMap::<u64, BTreeSet<u64>>::new();
    targets.entry(STATE_START_BLOCK).or_default();
    targets.entry(STATE_END_BLOCK).or_default();
    for funding in fundings {
        targets
            .entry(funding.block_number)
            .or_default()
            .insert(funding.transaction_index);
    }
    let mut blocks = Vec::new();
    let mut block_positions = BTreeMap::new();
    let mut receipt_positions = PositionMap::new();
    let mut transaction_positions = PositionMap::new();
    for (number, indices) in targets {
        let block_position = blocks.len();
        block_positions.insert(number, block_position);
        if indices.is_empty() {
            blocks.push(EnforcementBlock {
                header: client.header(number)?,
                receipts: Vec::new(),
                transactions: Vec::new(),
            });
            continue;
        }
        let indices = indices.into_iter().collect::<Vec<_>>();
        let (block, _) = client.enforcement_block_evidence(number, &indices, &indices, &[])?;
        for (position, receipt) in block.receipts.iter().enumerate() {
            receipt_positions.insert((number, receipt.tx_index), position);
        }
        for (position, transaction) in block.transactions.iter().enumerate() {
            transaction_positions.insert((number, transaction.tx_index), position);
        }
        blocks.push(block);
    }
    Ok((
        blocks,
        block_positions,
        receipt_positions,
        transaction_positions,
    ))
}

fn push_state_proof(
    client: &Client,
    blocks: &[EnforcementBlock],
    block_positions: &BTreeMap<u64, usize>,
    state_proofs: &mut Vec<Eip1186AccountProof>,
    block_number: u64,
    address: Address,
    slots: &[B256],
) -> Result<usize> {
    let block_position = *block_positions
        .get(&block_number)
        .context("state proof block missing")?;
    let proof = client.state_proof_chunked(
        block_position,
        block_number,
        address,
        slots,
        STATE_PROOF_CHUNK_SIZE,
    )?;
    if proof.block != block_position || blocks[block_position].header.number != block_number {
        bail!("state proof block mismatch");
    }
    let index = state_proofs.len();
    state_proofs.push(proof);
    Ok(index)
}

fn materialize_funder_accounts(
    client: &Client,
    blocks: &[EnforcementBlock],
    block_positions: &BTreeMap<u64, usize>,
    fundings: &[LocatedFunding],
    state_proofs: &mut Vec<Eip1186AccountProof>,
) -> Result<BTreeMap<(u64, Address), usize>> {
    let identities = fundings
        .iter()
        .map(|funding| (funding.block_number, funding.cohort_funder))
        .collect::<BTreeSet<_>>();
    let mut result = BTreeMap::new();
    for (block_number, funder) in identities {
        let index = push_state_proof(
            client,
            blocks,
            block_positions,
            state_proofs,
            block_number,
            funder,
            &[],
        )?;
        result.insert((block_number, funder), index);
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn build_funding_cohorts(
    buyers: &[Address],
    assignments: &BTreeMap<Address, (Address, FundingRecord)>,
    fundings: &[LocatedFunding],
    block_positions: &BTreeMap<u64, usize>,
    receipt_positions: &PositionMap,
    transaction_positions: &PositionMap,
    funding_account_indices: &BTreeMap<(u64, Address), usize>,
    deposits_account: usize,
    state_proofs: &[Eip1186AccountProof],
    client: &Client,
) -> Result<Vec<FunderCohort>> {
    let located = fundings
        .iter()
        .map(|funding| (funding.record.buyer(), funding))
        .collect::<BTreeMap<_, _>>();
    let mut cohorts = BTreeMap::<Address, Vec<Address>>::new();
    for buyer in buyers {
        cohorts
            .entry(
                assignments
                    .get(buyer)
                    .context("funding assignment missing")?
                    .0,
            )
            .or_default()
            .push(*buyer);
    }
    cohorts
        .into_iter()
        .map(|(funder, linked_buyers)| {
            let funding_evidence = linked_buyers
                .iter()
                .map(|buyer| {
                    let funding = located.get(buyer).context("located funding missing")?;
                    let block = *block_positions
                        .get(&funding.block_number)
                        .context("funding block missing")?;
                    let account = *funding_account_indices
                        .get(&(funding.block_number, funder))
                        .context("funding account proof missing")?;
                    let proof = &state_proofs[account];
                    let authentication = if proof.code_hash == alloy_trie::KECCAK_EMPTY {
                        FunderAuthentication::Eoa { account }
                    } else {
                        let code = client.code_at(funder, funding.block_number)?;
                        if code.len() != 23 || code[..3] != [0xef, 0x01, 0x00] || keccak256(&code) != proof.code_hash {
                            bail!("native funder {funder} is neither an EOA nor a supported EIP-7702 account");
                        }
                        FunderAuthentication::Eip7702 {
                            account,
                            delegation_code: code,
                        }
                    };
                    let receipt = *receipt_positions
                        .get(&(funding.block_number, funding.transaction_index))
                        .context("funding receipt proof missing")?;
                    let transaction = *transaction_positions
                        .get(&(funding.block_number, funding.transaction_index))
                        .context("funding transaction proof missing")?;
                    let kind = match funding.record {
                        FundingRecord::Native(_) => FundingKind::Native {
                            transaction: TransactionRef { block, transaction },
                            receipt: ReceiptRef { block, receipt },
                        },
                        FundingRecord::Protocol(_) => {
                            let (transfer, deposited) = funding
                                .protocol_logs
                                .context("protocol funding log positions missing")?;
                            FundingKind::ProtocolDeposit {
                                transfer: enforcement_core::LogRef {
                                    block,
                                    receipt,
                                    log: transfer,
                                },
                                deposited: enforcement_core::LogRef {
                                    block,
                                    receipt,
                                    log: deposited,
                                },
                            }
                        }
                    };
                    Ok(FundingEvidence {
                        buyer: *buyer,
                        first_channel_at: state_ref(
                            deposits_account,
                            enforcement_core::first_channel_slot(*buyer)
                                .map_err(anyhow::Error::msg)?,
                            state_proofs,
                        )?,
                        authentication,
                        kind,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(FunderCohort {
                funder,
                linked_buyers,
                fundings: funding_evidence,
            })
        })
        .collect()
}

fn counter_slots(seller: Address, buyers: &[Address], contract: Address) -> Result<Vec<B256>> {
    let mut slots = Vec::new();
    for epoch in 0..=MAX_EMISSIONS_EPOCH {
        slots.push(
            enforcement_core::counter_slot(CounterKind::Seller, seller, epoch, contract)
                .map_err(anyhow::Error::msg)?,
        );
    }
    for buyer in buyers {
        for epoch in 0..=MAX_EMISSIONS_EPOCH {
            slots.push(
                enforcement_core::counter_slot(CounterKind::Buyer, *buyer, epoch, contract)
                    .map_err(anyhow::Error::msg)?,
            );
        }
    }
    Ok(slots)
}

#[allow(clippy::too_many_arguments)]
fn build_counters(
    kind: CounterKind,
    subjects: &[Address],
    old_start_account: usize,
    old_end_account: usize,
    new_start_account: usize,
    new_end_account: usize,
    state_proofs: &[Eip1186AccountProof],
) -> Result<Vec<CounterDelta>> {
    let mut counters = Vec::new();
    for subject in subjects {
        for (contract, start_account, end_account) in [
            (OLD_EMISSIONS_ADDRESS, old_start_account, old_end_account),
            (NEW_EMISSIONS_ADDRESS, new_start_account, new_end_account),
        ] {
            for epoch in 0..=MAX_EMISSIONS_EPOCH {
                let slot = enforcement_core::counter_slot(kind, *subject, epoch, contract)
                    .map_err(anyhow::Error::msg)?;
                counters.push(CounterDelta {
                    kind,
                    subject: *subject,
                    contract,
                    epoch,
                    start: state_ref(start_account, slot, state_proofs)?,
                    end: state_ref(end_account, slot, state_proofs)?,
                });
            }
        }
    }
    Ok(counters)
}

fn state_ref(
    account: usize,
    slot: B256,
    state_proofs: &[Eip1186AccountProof],
) -> Result<StateValueRef> {
    let proof = state_proofs
        .get(account)
        .context("account proof index missing")?;
    let storage = if proof.exists {
        Some(
            proof
                .storage_proofs
                .binary_search_by_key(&slot, |proof| proof.slot)
                .map_err(|_| anyhow::anyhow!("storage proof slot {slot} missing"))?,
        )
    } else {
        None
    };
    Ok(StateValueRef {
        account,
        slot,
        storage,
    })
}

fn add_slot(slot: B256, offset: u64) -> Result<B256> {
    let value = U256::from_be_slice(slot.as_slice())
        .checked_add(U256::from(offset))
        .context("storage slot overflow")?;
    Ok(B256::from(value.to_be_bytes::<32>()))
}

fn primary_rpc_endpoints() -> Result<Vec<String>> {
    let endpoints = env::var("BASE_RPC_URL")
        .or_else(|_| env::var("BASE_ARCHIVE_RPC_URL"))
        .context("BASE_RPC_URL or BASE_ARCHIVE_RPC_URL is not configured")?;
    parse_rpc_endpoints(&endpoints, "primary RPC")
}

fn proof_rpc_endpoints() -> Result<Vec<String>> {
    let mut endpoints = Vec::new();
    for (variable, label) in [
        ("BASE_RPC_URL", "primary proof RPC"),
        ("BASE_ARCHIVE_RPC_URL", "archive proof RPC"),
    ] {
        if let Ok(value) = env::var(variable) {
            for endpoint in parse_rpc_endpoints(&value, label)? {
                if !endpoints.contains(&endpoint) {
                    endpoints.push(endpoint);
                }
            }
        }
    }
    if endpoints.is_empty() {
        bail!("BASE_RPC_URL or BASE_ARCHIVE_RPC_URL is not configured");
    }
    Ok(endpoints)
}

fn parse_rpc_endpoints(endpoints: &str, label: &str) -> Result<Vec<String>> {
    let endpoints = endpoints
        .split(',')
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        bail!("{label} contains no endpoints");
    }
    Ok(endpoints)
}

fn parse_addresses(value: String) -> Result<Vec<Address>> {
    let addresses = value
        .split(',')
        .map(|address| {
            address
                .trim()
                .parse::<Address>()
                .context("invalid funder address")
        })
        .collect::<Result<Vec<_>>>()?;
    if addresses.is_empty() {
        bail!("--funders contains no addresses");
    }
    Ok(addresses)
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn optional_arg(args: &[String], flag: &str) -> Option<String> {
    arg(args, flag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn record(buyer: Address, funder: Address) -> FundingRecord {
        FundingRecord::Native(NativeFundingRecord {
            buyer,
            from: funder,
            amount_wei: MINIMUM_NATIVE_FUNDING_WEI.to_string(),
            timestamp: 1,
            tx_hash: B256::ZERO,
        })
    }

    #[test]
    fn selection_keeps_three_buyers_per_selected_funder() {
        let funder_a = address!("0000000000000000000000000000000000000010");
        let funder_b = address!("0000000000000000000000000000000000000020");
        let buyers = [
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000004"),
            address!("0000000000000000000000000000000000000005"),
            address!("0000000000000000000000000000000000000006"),
        ];
        let assignments = buyers
            .iter()
            .enumerate()
            .map(|(index, buyer)| {
                let funder = if index < 3 { funder_a } else { funder_b };
                (*buyer, (funder, record(*buyer, funder)))
            })
            .collect::<BTreeMap<_, _>>();
        let channels = buyers
            .iter()
            .enumerate()
            .map(|(index, buyer)| SelectedChannel {
                channel_id: B256::from(U256::from(index + 1).to_be_bytes::<32>()),
                buyer: *buyer,
                scan_volume: if index < 3 { 200 } else { 100 },
            })
            .collect::<Vec<_>>();

        let (selected_buyers, _, volume) =
            select_threshold_witness(&channels, &assignments, 700).unwrap();
        assert_eq!(selected_buyers.len(), 6);
        assert_eq!(volume, 900);
    }

    #[test]
    fn self_funded_protocol_cohort_materializes_as_exact_funder() {
        let seller = address!("0000000000000000000000000000000000000010");
        let buyers = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let strongest = StrongestCohort {
            funder: seller,
            buyers: buyers.clone(),
        };
        let records = buyers
            .iter()
            .enumerate()
            .map(|(index, buyer)| ProtocolFundingRecord {
                buyer: *buyer,
                funder: seller,
                amount_raw: "1000000".into(),
                timestamp: index as u64 + 1,
                tx_hash: B256::from(U256::from(index + 1).to_be_bytes::<32>()),
            })
            .collect::<Vec<_>>();
        let assignments = funding_assignments(&[], Some(&strongest), &[], &records, None).unwrap();
        assert_eq!(assignments.len(), 3);
        assert!(assignments.values().all(|(funder, record)| {
            *funder == seller && matches!(record, FundingRecord::Protocol(_))
        }));
    }

    #[test]
    fn witness_package_uses_prover_schema() {
        let input = CoordinatedControlInput {
            chain_id: BASE_CHAIN_ID,
            seller: Address::ZERO,
            funding_cohorts: Vec::new(),
            blocks: Vec::new(),
            state_proofs: Vec::new(),
            channels: Vec::new(),
            seller_counters: Vec::new(),
            buyer_counters: Vec::new(),
        };
        let value = serde_json::to_value(WitnessPackage {
            version: PREDICATE_VERSION,
            kind: "antseed-wash-trading-proof-witness",
            enforceable: true,
            proof_type: "P1_COORDINATED_CONTROL",
            input: &input,
        })
        .unwrap();
        assert_eq!(value["proofType"], "P1_COORDINATED_CONTROL");
        assert!(value["input"]["chain_id"].is_number());
    }

    #[test]
    fn rpc_endpoint_lists_are_trimmed_and_nonempty() {
        assert_eq!(
            parse_rpc_endpoints(" https://one.example,https://two.example ", "test").unwrap(),
            vec!["https://one.example", "https://two.example"]
        );
        assert!(parse_rpc_endpoints(" , ", "test RPC").is_err());
    }
}
