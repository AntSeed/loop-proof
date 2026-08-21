include!(concat!(env!("OUT_DIR"), "/methods.rs"));

pub const EPOCH_GUEST_ELF: &[u8] = HISTORY_GUEST_ELF;
pub const EPOCH_IMAGE_ID: [u32; 8] = HISTORY_GUEST_ID;
