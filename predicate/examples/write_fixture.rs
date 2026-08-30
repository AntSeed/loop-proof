//! Writes the default synthetic closed-loop fixture (the same one the native
//! test suite proves and rejects around) for guest execution:
//! `cargo run -p wash-predicate --example write_fixture -- fixture.json`

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: write_fixture <out.json> [--reciprocal]");
    if std::env::args().any(|a| a == "--reciprocal") {
        let input = common::reciprocal_input(&common::PairCfg::default());
        wash_predicate::verify_reciprocal(&input).expect("fixture must satisfy the predicate");
        std::fs::write(&out, serde_json::to_vec(&input).unwrap()).unwrap();
    } else {
        let input = common::closed_loop_input(&common::LoopCfg::default());
        wash_predicate::verify_closed_loop(&input).expect("fixture must satisfy the predicate");
        std::fs::write(&out, serde_json::to_vec(&input).unwrap()).unwrap();
    }
    println!("fixture written to {out}");
}
