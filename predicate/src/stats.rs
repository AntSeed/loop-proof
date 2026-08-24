//! The ratio denominator: the subject's own settled volume, read from the
//! deployed `AntseedChannels.AgentStats` at the period-end block through the
//! same state-proof machinery as the `LEDGER` witness.
//!
//! `totalVolumeUsdc` accumulates the SAME `delta` word inside `settle()` that
//! the predicates sum from `ChannelSettled`, so the journal's numerator is by
//! construction a subset of this denominator. It is lifetime-cumulative and
//! monotonic, which is exactly why it must be read at the period end inside
//! the proof rather than live at policy-evaluation time: the ratio is fixed
//! at proving time and a subject cannot dilute it by accumulating volume
//! afterwards.

use crate::{
    resolver::ChainResolver, SellerStatsWitness, AGENT_STATS_TOTAL_VOLUME_OFFSET,
    CHANNELS_ADDRESS, CHANNELS_AGENT_STATS_SLOT, PERIOD_END_BLOCK, STAKING_ADDRESS,
    STAKING_SELLER_AGENT_ID_SLOT,
};
use alloy_primitives::Address;

/// Prove `Staking.sellerAgentId[subject]` at the period end; when non-zero,
/// prove `Channels._agentStats[agentId].totalVolumeUsdc` there too and return
/// it. A subject with no staked agent id has a zero denominator — proven,
/// not assumed — and the registry clamps its ratio to one.
pub fn verify_subject_stats(
    resolver: &ChainResolver<'_>,
    subject: Address,
    witness: &SellerStatsWitness,
) -> Result<u128, String> {
    let agent_slot =
        loop_core::mapping_slot_address(subject, STAKING_SELLER_AGENT_ID_SLOT);
    let agent_id = resolver.storage_value(
        &witness.agent_id_read,
        PERIOD_END_BLOCK,
        STAKING_ADDRESS,
        agent_slot,
    )?;
    if agent_id.is_zero() {
        if witness.stats_read.is_some() {
            return Err("stats: stats witness supplied for an agent-less subject".into());
        }
        return Ok(0);
    }
    let stats_read = witness
        .stats_read
        .as_ref()
        .ok_or("stats: settled-volume witness required for a staked subject")?;
    let volume_slot = loop_core::slot_offset(
        loop_core::mapping_slot_u256(agent_id, CHANNELS_AGENT_STATS_SLOT),
        AGENT_STATS_TOTAL_VOLUME_OFFSET,
    );
    let volume =
        resolver.storage_value(stats_read, PERIOD_END_BLOCK, CHANNELS_ADDRESS, volume_slot)?;
    u128::try_from(volume).map_err(|_| "stats: settled volume overflow".into())
}
