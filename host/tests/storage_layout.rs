//! Live cross-check of storage-layout constants the guest pins, against
//! Base mainnet.
//!
//! Run with:
//!   VERIFY_SELLER=0x0329c5d3920e301740f78d6e17b8d1a11cca9b2c \
//!     cargo test -p loop-host -- --ignored

#[test]
#[ignore = "hits live Base RPC endpoints"]
fn storage_layout_bindings_hold_on_mainnet() {
    let seller = std::env::var("VERIFY_SELLER")
        .expect("set VERIFY_SELLER=<address> to run this test");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_loop-host"))
        .arg("verify-layout")
        .arg(&seller)
        .status()
        .expect("spawn loop-host");
    assert!(status.success(), "storage-layout drift or RPC failure");
}
