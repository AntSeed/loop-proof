include!(concat!(env!("OUT_DIR"), "/methods.rs"));

pub const ACCUMULATOR_GUEST_ELF: &[u8] = CHECKPOINT_GUEST_ELF;
pub const ACCUMULATOR_IMAGE_ID: [u32; 8] = CHECKPOINT_GUEST_ID;
