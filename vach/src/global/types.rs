use anyhow;

// Private utility function
fn _contains(first: u16, other: u16) -> bool {
	!((first & other) == 0)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Flags {
	bits: u16,
}

// based on code in https://github.com/bitflags/bitflags/blob/main/src/lib.rs
// basically just a tiny, scoped version of bitflags
impl Flags {
	// Scoped constants
	pub const RESERVED_MASK: u16 = 0b1111_0000_0000_0000;
	pub const COMPRESSED_FLAG: u16 = 0b_1000_0000_0000_0000;
	pub const SIGNED_FLAG: u16 = 0b_0100_0000_0000_0000;

	#[inline(always)]
	pub fn from_bits(bits: u16) -> Self {
		Self { bits }
	}
	#[inline(always)]
	pub fn bits(&self) -> u16 {
		self.bits
	}
	#[inline(always)]
	pub fn empty() -> Self {
		Self { bits: 0 }
	}

	/// Returns a error if mask contains a reserved bit
	pub fn set(&mut self, mask: u16, toggle: bool) -> anyhow::Result<u16> {
		if _contains(Flags::RESERVED_MASK, mask) {
			anyhow::bail!("Tried to set reserved bit(s)!");
		} else {
			self.force_set(mask, toggle)
		}

		Ok(self.bits)
	}
	pub(crate) fn force_set(&mut self, mask: u16, toggle: bool) {
		if toggle {
			 self.bits |= mask;
		} else {
			 self.bits &= !mask;
		}
  }

	#[inline(always)]
	pub fn contains(&self, mask: u16) -> bool {
		_contains(self.bits, mask)
	}
}

impl Default for Flags {
	#[inline(always)]
	fn default() -> Self {
		Self { bits: 0 }
	}
}
