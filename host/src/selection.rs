use crate::rpc::SettlementCandidate;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const AGGREGATE_VERIFIER_START_BLOCK: u64 = 46_302_960;
pub const CHECKPOINT_WINDOW_BLOCKS: u64 = 30;

#[derive(Clone, Debug)]
pub struct BuyerSettlementCandidate {
    pub buyer_index: usize,
    pub settlement: SettlementCandidate,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SelectedCheckpointWindow {
    pub checkpoint_block_number: u64,
    pub target_blocks: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct SelectionResult {
    pub selected_candidate_indices: Vec<usize>,
    pub selected_volume_raw: u128,
    pub checkpoint_windows: Vec<SelectedCheckpointWindow>,
}

#[derive(Clone, Debug)]
struct CandidateWindow {
    checkpoint_block_number: u64,
    candidate_indices: Vec<usize>,
    buyer_mask: u64,
    volume_raw: u128,
}

#[derive(Clone, Debug)]
struct OptimizationState {
    volume_raw: u128,
    receipt_count: usize,
    group_counts: Vec<usize>,
}

pub fn checkpoint_block_number(block_number: u64) -> Result<u64, String> {
    if block_number <= AGGREGATE_VERIFIER_START_BLOCK {
        return Err(format!(
            "block {block_number} predates AggregateVerifier checkpoint coverage"
        ));
    }
    let offset = block_number - AGGREGATE_VERIFIER_START_BLOCK - 1;
    AGGREGATE_VERIFIER_START_BLOCK
        .checked_add((offset / CHECKPOINT_WINDOW_BLOCKS + 1) * CHECKPOINT_WINDOW_BLOCKS)
        .ok_or_else(|| "checkpoint block overflow".to_string())
}

pub fn select_minimum_windows(
    candidates: &[BuyerSettlementCandidate],
    fixed_blocks: &[u64],
    buyer_count: usize,
    minimum_volume_raw: u128,
) -> Result<SelectionResult, String> {
    if buyer_count == 0 || buyer_count >= u64::BITS as usize {
        return Err("selector requires between 1 and 63 buyers".into());
    }
    if candidates.is_empty() {
        return Err("no eligible settlement candidates".into());
    }

    let full_buyer_mask = (1_u64 << buyer_count) - 1;
    let fixed_checkpoints = fixed_blocks
        .iter()
        .map(|block_number| checkpoint_block_number(*block_number))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut windows_by_checkpoint = BTreeMap::<u64, CandidateWindow>::new();
    let mut canonical_locations = BTreeSet::new();

    for (candidate_index, candidate) in candidates.iter().enumerate() {
        if candidate.buyer_index >= buyer_count {
            return Err(format!(
                "candidate buyer index {} exceeds buyer count {buyer_count}",
                candidate.buyer_index
            ));
        }
        if !canonical_locations.insert(candidate.settlement.canonical_key()) {
            return Err("duplicate settlement candidate".into());
        }
        let checkpoint = checkpoint_block_number(candidate.settlement.block_number)?;
        let window = windows_by_checkpoint
            .entry(checkpoint)
            .or_insert_with(|| CandidateWindow {
                checkpoint_block_number: checkpoint,
                candidate_indices: Vec::new(),
                buyer_mask: 0,
                volume_raw: 0,
            });
        window.candidate_indices.push(candidate_index);
        window.buyer_mask |= 1_u64 << candidate.buyer_index;
        window.volume_raw = window
            .volume_raw
            .checked_add(candidate.settlement.amount_raw)
            .ok_or_else(|| "candidate window volume overflow".to_string())?;
    }

    let mut selected_checkpoints = fixed_checkpoints.clone();
    let mut base_volume_raw = 0_u128;
    let mut base_buyer_mask = 0_u64;
    let mut grouped_windows = BTreeMap::<u64, Vec<CandidateWindow>>::new();

    for window in windows_by_checkpoint.values() {
        if fixed_checkpoints.contains(&window.checkpoint_block_number) {
            base_volume_raw = base_volume_raw
                .checked_add(window.volume_raw)
                .ok_or_else(|| "fixed window volume overflow".to_string())?;
            base_buyer_mask |= window.buyer_mask;
        } else {
            grouped_windows
                .entry(window.buyer_mask)
                .or_default()
                .push(window.clone());
        }
    }

    let mut groups = grouped_windows.into_values().collect::<Vec<_>>();
    for windows in &mut groups {
        windows.sort_by(|left, right| {
            right
                .volume_raw
                .cmp(&left.volume_raw)
                .then_with(|| {
                    left.candidate_indices
                        .len()
                        .cmp(&right.candidate_indices.len())
                })
                .then_with(|| {
                    left.checkpoint_block_number
                        .cmp(&right.checkpoint_block_number)
                })
        });
    }
    groups.sort_by_key(|windows| windows[0].buyer_mask);

    let mut states = HashMap::from([(
        (0_usize, base_buyer_mask),
        OptimizationState {
            volume_raw: base_volume_raw,
            receipt_count: 0,
            group_counts: Vec::new(),
        },
    )]);

    for windows in &groups {
        let mut prefix_volume = Vec::with_capacity(windows.len() + 1);
        let mut prefix_receipts = Vec::with_capacity(windows.len() + 1);
        prefix_volume.push(0_u128);
        prefix_receipts.push(0_usize);
        for window in windows {
            prefix_volume.push(
                prefix_volume
                    .last()
                    .copied()
                    .unwrap()
                    .checked_add(window.volume_raw)
                    .ok_or_else(|| "candidate volume overflow".to_string())?,
            );
            prefix_receipts
                .push(prefix_receipts.last().copied().unwrap() + window.candidate_indices.len());
        }

        let mut next_states = HashMap::new();
        for ((selected_count, buyer_mask), state) in &states {
            for take_count in 0..=windows.len() {
                let next_count = selected_count + take_count;
                let next_mask = if take_count == 0 {
                    *buyer_mask
                } else {
                    *buyer_mask | windows[0].buyer_mask
                };
                let next_volume = state
                    .volume_raw
                    .checked_add(prefix_volume[take_count])
                    .ok_or_else(|| "selected volume overflow".to_string())?;
                let next_receipts = state.receipt_count + prefix_receipts[take_count];
                let mut group_counts = state.group_counts.clone();
                group_counts.push(take_count);
                let candidate_state = OptimizationState {
                    volume_raw: next_volume,
                    receipt_count: next_receipts,
                    group_counts,
                };
                let key = (next_count, next_mask);
                if next_states
                    .get(&key)
                    .is_none_or(|existing| better_state(&candidate_state, existing))
                {
                    next_states.insert(key, candidate_state);
                }
            }
        }
        states = next_states;
    }

    let selected_state = states
        .into_iter()
        .filter(|((_, buyer_mask), state)| {
            *buyer_mask == full_buyer_mask && state.volume_raw >= minimum_volume_raw
        })
        .min_by(|((left_count, _), left), ((right_count, _), right)| {
            left_count
                .cmp(right_count)
                .then_with(|| right.volume_raw.cmp(&left.volume_raw))
                .then_with(|| left.receipt_count.cmp(&right.receipt_count))
                .then_with(|| left.group_counts.cmp(&right.group_counts))
        })
        .map(|(_, state)| state)
        .ok_or_else(|| {
            "eligible settlements cannot satisfy buyer coverage and minimum volume".to_string()
        })?;

    for (windows, take_count) in groups.iter().zip(&selected_state.group_counts) {
        selected_checkpoints.extend(
            windows
                .iter()
                .take(*take_count)
                .map(|window| window.checkpoint_block_number),
        );
    }

    let selected_candidate_indices = select_minimum_receipts(
        candidates,
        &selected_checkpoints,
        buyer_count,
        minimum_volume_raw,
    )?;
    let selected_volume_raw =
        selected_candidate_indices
            .iter()
            .try_fold(0_u128, |total, candidate_index| {
                total
                    .checked_add(candidates[*candidate_index].settlement.amount_raw)
                    .ok_or_else(|| "selected receipt volume overflow".to_string())
            })?;

    let mut target_blocks_by_checkpoint = fixed_blocks.iter().try_fold(
        BTreeMap::<u64, BTreeSet<u64>>::new(),
        |mut result, block_number| {
            result
                .entry(checkpoint_block_number(*block_number)?)
                .or_default()
                .insert(*block_number);
            Ok::<_, String>(result)
        },
    )?;
    for candidate_index in &selected_candidate_indices {
        let block_number = candidates[*candidate_index].settlement.block_number;
        target_blocks_by_checkpoint
            .entry(checkpoint_block_number(block_number)?)
            .or_default()
            .insert(block_number);
    }

    let checkpoint_windows = target_blocks_by_checkpoint
        .into_iter()
        .map(
            |(checkpoint_block_number, target_blocks)| SelectedCheckpointWindow {
                checkpoint_block_number,
                target_blocks: target_blocks.into_iter().collect(),
            },
        )
        .collect();

    Ok(SelectionResult {
        selected_candidate_indices,
        selected_volume_raw,
        checkpoint_windows,
    })
}

fn better_state(candidate: &OptimizationState, existing: &OptimizationState) -> bool {
    candidate.volume_raw > existing.volume_raw
        || (candidate.volume_raw == existing.volume_raw
            && (candidate.receipt_count < existing.receipt_count
                || (candidate.receipt_count == existing.receipt_count
                    && candidate.group_counts < existing.group_counts)))
}

fn select_minimum_receipts(
    candidates: &[BuyerSettlementCandidate],
    selected_checkpoints: &BTreeSet<u64>,
    buyer_count: usize,
    minimum_volume_raw: u128,
) -> Result<Vec<usize>, String> {
    let eligible_indices = candidates
        .iter()
        .enumerate()
        .filter_map(|(candidate_index, candidate)| {
            let checkpoint = checkpoint_block_number(candidate.settlement.block_number).ok()?;
            selected_checkpoints
                .contains(&checkpoint)
                .then_some(candidate_index)
        })
        .collect::<Vec<_>>();
    let mut selected = BTreeSet::new();

    for buyer_index in 0..buyer_count {
        let best = eligible_indices
            .iter()
            .copied()
            .filter(|candidate_index| candidates[*candidate_index].buyer_index == buyer_index)
            .max_by(|left_index, right_index| {
                let left = &candidates[*left_index].settlement;
                let right = &candidates[*right_index].settlement;
                left.amount_raw
                    .cmp(&right.amount_raw)
                    .then_with(|| right.canonical_key().cmp(&left.canonical_key()))
            })
            .ok_or_else(|| {
                format!("selected windows contain no settlement for buyer {buyer_index}")
            })?;
        selected.insert(best);
    }

    let mut selected_volume = selected.iter().try_fold(0_u128, |total, candidate_index| {
        total
            .checked_add(candidates[*candidate_index].settlement.amount_raw)
            .ok_or_else(|| "selected receipt volume overflow".to_string())
    })?;
    let mut remaining = eligible_indices
        .into_iter()
        .filter(|candidate_index| !selected.contains(candidate_index))
        .collect::<Vec<_>>();
    remaining.sort_by(|left_index, right_index| {
        let left = &candidates[*left_index].settlement;
        let right = &candidates[*right_index].settlement;
        right
            .amount_raw
            .cmp(&left.amount_raw)
            .then_with(|| left.canonical_key().cmp(&right.canonical_key()))
    });
    for candidate_index in remaining {
        if selected_volume >= minimum_volume_raw {
            break;
        }
        selected.insert(candidate_index);
        selected_volume = selected_volume
            .checked_add(candidates[candidate_index].settlement.amount_raw)
            .ok_or_else(|| "selected receipt volume overflow".to_string())?;
    }
    if selected_volume < minimum_volume_raw {
        return Err("selected windows do not contain enough settlement volume".into());
    }

    let mut result = selected.into_iter().collect::<Vec<_>>();
    result.sort_by_key(|candidate_index| candidates[*candidate_index].settlement.canonical_key());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn candidate(
        buyer_index: usize,
        block_number: u64,
        amount_raw: u128,
    ) -> BuyerSettlementCandidate {
        BuyerSettlementCandidate {
            buyer_index,
            settlement: SettlementCandidate {
                block_number,
                transaction_hash: B256::with_last_byte((block_number % 255) as u8),
                transaction_index: 0,
                block_log_index: block_number,
                amount_raw,
            },
        }
    }

    #[test]
    fn aligns_checkpoint_boundaries() {
        assert!(checkpoint_block_number(AGGREGATE_VERIFIER_START_BLOCK).is_err());
        assert_eq!(
            checkpoint_block_number(AGGREGATE_VERIFIER_START_BLOCK + 1).unwrap(),
            AGGREGATE_VERIFIER_START_BLOCK + 30
        );
        assert_eq!(
            checkpoint_block_number(AGGREGATE_VERIFIER_START_BLOCK + 30).unwrap(),
            AGGREGATE_VERIFIER_START_BLOCK + 30
        );
        assert_eq!(
            checkpoint_block_number(AGGREGATE_VERIFIER_START_BLOCK + 31).unwrap(),
            AGGREGATE_VERIFIER_START_BLOCK + 60
        );
    }

    #[test]
    fn chooses_exact_minimum_windows() {
        let base = AGGREGATE_VERIFIER_START_BLOCK;
        let candidates = vec![
            candidate(0, base + 1, 400),
            candidate(1, base + 2, 100),
            candidate(2, base + 31, 350),
            candidate(0, base + 61, 900),
            candidate(1, base + 62, 1),
            candidate(2, base + 63, 1),
        ];
        let result = select_minimum_windows(&candidates, &[], 3, 800).unwrap();

        assert_eq!(result.checkpoint_windows.len(), 1);
        assert_eq!(
            result.checkpoint_windows[0].checkpoint_block_number,
            base + 90
        );
        assert_eq!(result.selected_candidate_indices.len(), 3);
        assert_eq!(result.selected_volume_raw, 902);
    }

    #[test]
    fn treats_fixed_windows_as_zero_marginal_cost() {
        let base = AGGREGATE_VERIFIER_START_BLOCK;
        let candidates = vec![
            candidate(0, base + 1, 300),
            candidate(1, base + 2, 300),
            candidate(2, base + 3, 400),
            candidate(0, base + 31, 2_000),
        ];
        let result = select_minimum_windows(&candidates, &[base + 4], 3, 1_000).unwrap();

        assert_eq!(result.checkpoint_windows.len(), 1);
        assert_eq!(result.selected_volume_raw, 1_000);
    }

    #[test]
    fn fails_without_buyer_coverage() {
        let base = AGGREGATE_VERIFIER_START_BLOCK;
        let candidates = vec![candidate(0, base + 1, 1_000), candidate(1, base + 2, 1_000)];
        let error = select_minimum_windows(&candidates, &[], 3, 1_000).unwrap_err();
        assert!(error.contains("cannot satisfy buyer coverage"));
    }

    #[test]
    fn fails_with_insufficient_volume() {
        let base = AGGREGATE_VERIFIER_START_BLOCK;
        let candidates = vec![
            candidate(0, base + 1, 100),
            candidate(1, base + 31, 100),
            candidate(2, base + 61, 100),
        ];

        let error = select_minimum_windows(&candidates, &[], 3, 301).unwrap_err();
        assert!(error.contains("minimum volume"));
    }

    #[test]
    fn resolves_equal_volume_ties_deterministically() {
        let base = AGGREGATE_VERIFIER_START_BLOCK;
        let candidates = vec![
            candidate(0, base + 31, 400),
            candidate(1, base + 32, 300),
            candidate(2, base + 33, 300),
            candidate(0, base + 1, 400),
            candidate(1, base + 2, 300),
            candidate(2, base + 3, 300),
        ];

        let first = select_minimum_windows(&candidates, &[], 3, 1_000).unwrap();
        let second = select_minimum_windows(&candidates, &[], 3, 1_000).unwrap();

        assert_eq!(
            first.selected_candidate_indices,
            second.selected_candidate_indices
        );
        assert_eq!(first.checkpoint_windows, second.checkpoint_windows);
        assert_eq!(
            first.checkpoint_windows[0].checkpoint_block_number,
            base + CHECKPOINT_WINDOW_BLOCKS
        );
    }
}
