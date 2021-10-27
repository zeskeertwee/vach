use std::fmt;
use anyhow;

// Private utility function
fn _contains(first: u16, other: u16) -> bool {
	(first & other) != 0
}

/// Abstracted flag access and manipulation `struct`.
/// A knock-off minimal bitflags of sorts.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Flags {
	pub(crate) bits: u16,
}

// based on code in https://github.com/bitflags/bitflags/blob/main/src/lib.rs
// basically just a tiny, scoped version of bitflags
impl Flags {
	/// The flags used within the crate, to whom all access is denied.
	/// Any interaction with set will cause an exception.
	pub const RESERVED_MASK: u16 = 0b1111_0000_0000_0000;
	/// The flag that represents compressed sources
	pub const COMPRESSED_FLAG: u16 = 0b_1000_0000_0000_0000;
	/// The flag that denotes that the archive source has signatures
	pub const SIGNED_FLAG: u16 = 0b_0100_0000_0000_0000;
	/// The flag that marks registry entries as links rather than leaf pointers
	pub const LINK_FLAG: u16 = 0b_0010_0000_0000_0000;
	/// The flag that shows data in the leaf in encrypted
	pub const ENCRYPTED_FLAG: u16 = 0b_0001_0000_0000_0000;

	#[inline(always)]
	/// Construct a `Flags` struct from a `u16` number
	pub fn from_bits(bits: u16) -> Self {
		Flags { bits }
	}
	/// Returns a copy of the underlying number.
	#[inline(always)]
	pub fn bits(&self) -> u16 {
		self.bits
	}
	/// Yield a new empty `Flags` instance.
	/// ```
	/// use vach::prelude::Flags;
	/// let flag = Flags::from_bits(0b0000_0000_0000_0000);
	/// assert_eq!(Flags::empty(), flag);
	/// ```
	#[inline(always)]
	pub fn empty() -> Self {
		Flags { bits: 0 }
	}

	/// Returns a error if mask contains a reserved bit.
	/// Set a flag into the underlying structure.
	/// The `toggle` parameter specifies whether to insert the flags (when true), or to pop the flag, (when false).
	/// ```
	/// use vach::prelude::Flags;
	///
	/// let mut flag = Flags::from_bits(0b0000_0000_0000_0000);
	/// flag.set(0b0000_1000_0000_0000, true);
	/// flag.set(0b0000_0000_1000_0000, true);
	/// assert_eq!(flag.bits(), 0b0000_1000_1000_0000);
	///
	/// // --------------------------v---------
	/// flag.set(0b0000_1000_0000_0001, false); // 0 flags remain zero
	/// assert_eq!(flag.bits(), 0b0000_0000_1000_0000);
	/// ```
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
	/// Checks whether the given flag is set.
	/// ```rust
	/// use vach::prelude::Flags;
	///
	/// let mut flag = Flags::from_bits(0b0000_0000_0000_0000);
	///
	/// flag.set(0b0000_1000_0000_0000, true);
	/// assert!(flag.contains(0b0000_1000_0000_0000));
	/// ```
	pub fn contains(&self, mask: u16) -> bool {
		_contains(self.bits, mask)
	}
}

impl Default for Flags {
	#[inline(always)]
	fn default() -> Self {
		Flags { bits: 0 }
	}
}

impl fmt::Display for Flags {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let compressed = if self.contains(Flags::COMPRESSED_FLAG) { 'C' } else { '-' };
		let signed = if self.contains(Flags::SIGNED_FLAG) { 'S' } else { '-' };
		let encrypted = if self.contains(Flags::ENCRYPTED_FLAG) { 'E' } else { '-' };

		write!(f, "Flags[{}{}{}]: {:#016b}", compressed, encrypted, signed, self.bits)
	}
}

impl fmt::Debug for Flags {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(&self, f)
	}
}
