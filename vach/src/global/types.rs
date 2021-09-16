use anyhow::{Result, bail};

pub const RESERVED_MASK: u16 = 0b1111_0000_0000_0000;
pub const COMPRESSED_FLAG: u16 = 0b_1000_0000_0000_0000;
pub const SIGNED_FLAG: u16 = 0b_0100_0000_0000_0000;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Flags {
    bits: u16,
}

// based on code in https://github.com/bitflags/bitflags/blob/main/src/lib.rs
// basically just a tiny version of bitflags
impl Flags {
    pub(crate) fn from_bits(bits: u16) -> Self {
        Self {
            bits,
        }
    }

    pub fn bits(&self) -> u16 {
        self.bits
    }

    pub(crate) fn _set(&mut self, mask: u16, value: bool) {
        if value {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }

    /// returns a error if mask contains a reserved bit
    pub fn set(&mut self, mask: u16, value: bool) -> anyhow::Result<()> {
        if _contains(RESERVED_MASK, mask) {
            bail!("Tried to set reserved bit(s)!");
        } else {
            self._set(mask, value);
        }

        Ok(())
    }

    pub fn contains(&self, mask: u16) -> bool {
        _contains(self.bits, mask)
    }
}

fn _contains(first: u16, other: u16) -> bool {
    !((first & other) == 0)
}

impl Default for Flags {
    fn default() -> Self {
        Self {
            bits: 0,
        }
    }
}

#[test]
fn bitflags_reserved_protection() {
    let initial_flags = 0b1111_1000_0000_0000;
    let custom_flag = 0b0000_0000_0000_0100;
    let mut flag = Flags { bits: initial_flags };
    assert!(flag.set(COMPRESSED_FLAG, true).is_err());
    assert!(flag.contains(initial_flags));
    assert!(flag.set(custom_flag, true).is_ok());
}

#[test]
fn bitflags_set_intersects() {
    let mut flag = Flags::default();
    flag._set(COMPRESSED_FLAG, true);
    assert_eq!(flag.bits, COMPRESSED_FLAG);
    flag._set(COMPRESSED_FLAG, true);
    assert_eq!(flag.bits, COMPRESSED_FLAG);
    flag._set(SIGNED_FLAG, true);
    assert_eq!(flag.bits, COMPRESSED_FLAG | SIGNED_FLAG);
    flag._set(COMPRESSED_FLAG, false);
    assert_eq!(flag.bits, SIGNED_FLAG);
    flag._set(COMPRESSED_FLAG, false);
    assert_eq!(flag.bits, SIGNED_FLAG);
    flag._set(COMPRESSED_FLAG | SIGNED_FLAG, true);
    assert_eq!(flag.bits, COMPRESSED_FLAG | SIGNED_FLAG);
}