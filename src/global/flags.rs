use bitflags::bitflags;

bitflags! {
	#[derive(Default)]
    pub struct Flags: u16 {
            const SIGNED = 0b_0100_0000_0000_0000;
            const COMPRESSED = 0b_1000_0000_0000_0000;
    }
}
