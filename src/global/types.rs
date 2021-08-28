use bitflags::bitflags;

pub type RegisterType = u64;
bitflags! {
	#[derive(Default)]
    pub struct FlagType: u16 {
            const SIGNED = 0b_0100_0000_0000_0000;
            const COMPRESSED = 0b_1000_0000_0000_0000;
    }
}
