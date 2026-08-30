//! The subject's exact period volume, derived from authenticated cumulative
//! `AntseedChannels.AgentStats` values at both boundaries.
//!
//! `totalVolumeUsdc` accumulates the SAME `delta` word inside `settle()` that
//! the predicates sum from `ChannelSettled`, so the journal's numerator is by
//! construction a subset of this denominator. It is lifetime-cumulative and
//! monotonic, so subtracting the pre-period value from the period-end value
//! authenticates the exact range total.

use crate::{
    resolver::ChainResolver, SellerStatsWitness, AGENT_STATS_TOTAL_VOLUME_OFFSET, CHANNELS_ADDRESS,
    CHANNELS_AGENT_STATS_SLOT, STAKING_ADDRESS, STAKING_SELLER_AGENT_ID_SLOT,
};
use alloy_primitives::{Address, U256};

/// Prove the period-end agent ID and cumulative volume at both boundaries.
pub fn verify_subject_stats(
    resolver: &ChainResolver<'_>,
    subject: Address,
    witness: &SellerStatsWitness,
    period_start_block: u64,
    period_end_block: u64,
) -> Result<(U256, u128), String> {
    let agent_slot = loop_core::mapping_slot_address(subject, STAKING_SELLER_AGENT_ID_SLOT);
    let agent_id = resolver.storage_value(
        &witness.end_agent_id_read,
        period_end_block,
        STAKING_ADDRESS,
        agent_slot,
    )?;
    if agent_id.is_zero() {
        return Err("stats: subject has no agent id".into());
    }
    let volume_slot = loop_core::slot_offset(
        loop_core::mapping_slot_u256(agent_id, CHANNELS_AGENT_STATS_SLOT),
        AGENT_STATS_TOTAL_VOLUME_OFFSET,
    );
    let start = resolver.storage_value(
        &witness.start_volume_read,
        period_start_block - 1,
        CHANNELS_ADDRESS,
        volume_slot,
    )?;
    let end = resolver.storage_value(
        &witness.end_volume_read,
        period_end_block,
        CHANNELS_ADDRESS,
        volume_slot,
    )?;
    let delta = end
        .checked_sub(start)
        .ok_or("stats: cumulative volume decreased")?;
    Ok((
        agent_id,
        u128::try_from(delta).map_err(|_| "stats: volume overflow")?,
    ))
}
