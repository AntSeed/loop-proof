#[path = "../tests/common/mod.rs"]
mod common;

use anyhow::{Context, Result};
use common::{closed_loop_input, reciprocal_input, LoopCfg, PairCfg};
use std::{env, fs, path::PathBuf};

fn main() -> Result<()> {
    let output = env::args()
        .skip(1)
        .find_map(|value| value.strip_prefix("--output=").map(PathBuf::from))
        .context("usage: generate_development_fixtures --output=DIR")?;
    fs::create_dir_all(&output)?;

    let mut reciprocal = reciprocal_input(&PairCfg::default());
    let reciprocal_offset = wash_predicate::PERIOD_END_BLOCK
        .checked_sub(wash_predicate::PERIOD_START_BLOCK)
        .and_then(|span| span.checked_add(2))
        .context("reciprocal fixture block offset overflow")?;
    reciprocal.period_start_block += reciprocal_offset;
    reciprocal.period_end_block += reciprocal_offset;
    for block in &mut reciprocal.blocks {
        block.header.number += reciprocal_offset;
    }

    let fixtures = [
        (
            "closed-loop.json",
            serde_json::to_vec(&closed_loop_input(&LoopCfg::default()))?,
        ),
        ("reciprocal.json", serde_json::to_vec(&reciprocal)?),
    ];
    for (name, bytes) in fixtures {
        let path = output.join(name);
        fs::write(&path, bytes)?;
        println!("{}", path.display());
    }
    Ok(())
}
