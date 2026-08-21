use alloy::primitives::Address;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const STATE_PLAN_VERSION: u32 = 1;
pub const STATE_PLAN_KIND: &str = "antseed-base-state-plan";
pub const BASE_CHAIN_ID: u64 = 8_453;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatePlan {
    pub version: u32,
    pub kind: String,
    pub chain_id: u64,
    pub oracle: Address,
    pub entries: Vec<StatePlanEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatePlanEntry {
    pub id: String,
    pub order: usize,
    pub purpose: String,
    pub to: Address,
    pub value: String,
    pub data: String,
    pub checks: Vec<StatePlanCheck>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatePlanCheck {
    pub to: Address,
    pub data: String,
    pub expected: String,
}

impl StatePlan {
    pub fn new(chain_id: u64, oracle: Address, entries: Vec<StatePlanEntry>) -> Result<Self> {
        let plan = Self {
            version: STATE_PLAN_VERSION,
            kind: STATE_PLAN_KIND.into(),
            chain_id,
            oracle,
            entries,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == STATE_PLAN_VERSION,
            "unsupported state plan version"
        );
        ensure!(self.kind == STATE_PLAN_KIND, "unsupported state plan kind");
        ensure!(
            self.chain_id == BASE_CHAIN_ID,
            "state plan is not for Base mainnet"
        );
        ensure!(self.oracle != Address::ZERO, "state plan oracle is zero");
        ensure!(!self.entries.is_empty(), "state plan has no entries");
        let mut ids = BTreeSet::new();
        for (order, entry) in self.entries.iter().enumerate() {
            ensure!(entry.order == order, "state plan order is not contiguous");
            ensure!(
                !entry.id.is_empty() && ids.insert(&entry.id),
                "duplicate or empty state plan id"
            );
            ensure!(
                !entry.purpose.is_empty(),
                "state plan entry purpose is empty"
            );
            ensure!(
                entry.to == self.oracle,
                "state plan entry targets a different oracle"
            );
            ensure!(entry.value == "0x0", "state plan entry sends value");
            ensure!(
                valid_hex(&entry.data, 4),
                "state plan entry calldata is invalid"
            );
            ensure!(
                !entry.checks.is_empty(),
                "state plan entry has no completion checks"
            );
            for check in &entry.checks {
                ensure!(
                    check.to == self.oracle,
                    "state plan check targets a different oracle"
                );
                ensure!(
                    valid_hex(&check.data, 4),
                    "state plan check calldata is invalid"
                );
                ensure!(
                    exact_hex(&check.expected, 32),
                    "state plan check result is invalid"
                );
            }
        }
        Ok(())
    }
}

pub fn entry(
    id: impl Into<String>,
    order: usize,
    purpose: impl Into<String>,
    oracle: Address,
    data: &[u8],
    checks: Vec<StatePlanCheck>,
) -> StatePlanEntry {
    StatePlanEntry {
        id: id.into(),
        order,
        purpose: purpose.into(),
        to: oracle,
        value: "0x0".into(),
        data: hex(data),
        checks,
    }
}

pub fn check(oracle: Address, data: &[u8], expected: &[u8]) -> StatePlanCheck {
    StatePlanCheck {
        to: oracle,
        data: hex(data),
        expected: hex(expected),
    }
}

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(bytes))
}

fn valid_hex(value: &str, minimum_bytes: usize) -> bool {
    let Some(value) = value.strip_prefix("0x") else {
        return false;
    };
    value.len() >= minimum_bytes * 2
        && value.len() % 2 == 0
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn exact_hex(value: &str, bytes: usize) -> bool {
    valid_hex(value, bytes) && value.len() == 2 + bytes * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn validates_strict_plan_shape() {
        let oracle = address!("0000000000000000000000000000000000000001");
        let plan = StatePlan::new(
            8_453,
            oracle,
            vec![entry(
                "checkpoint:1",
                0,
                "checkpoint",
                oracle,
                &[1, 2, 3, 4],
                vec![check(oracle, &[5, 6, 7, 8], &[0; 32])],
            )],
        )
        .unwrap();
        assert_eq!(plan.kind, STATE_PLAN_KIND);
    }

    #[test]
    fn rejects_noncontiguous_and_unchecked_entries() {
        let oracle = address!("0000000000000000000000000000000000000001");
        let mut unchecked = entry("one", 0, "one", oracle, &[1, 2, 3, 4], vec![]);
        assert!(StatePlan::new(8_453, oracle, vec![unchecked.clone()]).is_err());
        unchecked.order = 1;
        unchecked
            .checks
            .push(check(oracle, &[5, 6, 7, 8], &[0; 32]));
        assert!(StatePlan::new(8_453, oracle, vec![unchecked]).is_err());
        assert!(
            StatePlan::new(
                1,
                oracle,
                vec![entry(
                    "one",
                    0,
                    "one",
                    oracle,
                    &[1, 2, 3, 4],
                    vec![check(oracle, &[5, 6, 7, 8], &[0; 32])],
                )]
            )
            .is_err()
        );
    }
}
