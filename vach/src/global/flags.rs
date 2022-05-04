use std::fmt;
use super::{error::InternalError, result::InternalResult};

/// Abstracted flag access and manipulation `struct`.
/// A knock-off minimal bitflags of sorts.
#[derive(Copy, Clone, Default, PartialEq)]
pub struct Flags {
	pub(crate) bits: u32,
}

// based on code in https://github.com/bitflags/bitflags/blob/main/src/lib.rs
// basically just a tiny, scoped version of bitflags
impl Flags {
	/// The flags used within the crate, to whom all access is denied.
	/// Any interaction with `Flags::set()` will yield an error.
	pub const RESERVED_MASK: u32 = 0b1111_1111_1111_1111_0000_0000_0000_0000;
	/// The size in bytes of any flags entry
	pub const SIZE: usize = 32 / 8;

	/// This flag shows that the adjacent entry is compressed
	pub const COMPRESSED_FLAG: u32 = 0b_1000_0000_0000_0000_0000_0000_0000_0000;
	/// This entry was compressed using the [LZ4](https://crates.io/crates/lz4_flex) scheme for very fast decompression with average compression ratios
	pub const LZ4_COMPRESSED: u32 = 0b_0100_0000_0000_0000_0000_0000_0000_0000;
	/// This entry was compressed using the [snappy](https://crates.io/crates/snap) scheme for balanced compression properties
	pub const SNAPPY_COMPRESSED: u32 = 0b_0010_0000_0000_0000_0000_0000_0000_0000;
	/// This entry was compressed using the [brotli](https://crates.io/crates/brotli) scheme for higher compression ratios but *much* (depends on the quality of compression) slower compression speed
	pub const BROTLI_COMPRESSED: u32 = 0b_0001_0000_0000_0000_0000_0000_0000_0000;

	/// The flag that denotes that the archive source has signatures
	pub const SIGNED_FLAG: u32 = 0b_0000_1000_0000_0000_0000_0000_0000_0000;
	/// The flag that shows data in the leaf in encrypted
	pub const ENCRYPTED_FLAG: u32 = 0b_0000_0010_0000_0000_0000_0000_0000_0000;
	/// A flag that is set if the registry has space reserved for more entries
	pub const MUTABLE_REGISTRY_FLAG: u32 = 0b_0000_0001_0000_0000_0000_0000_0000_0000;

	#[inline(always)]
	/// Construct a `Flags` struct from a `u32` number
	pub fn from_bits(bits: u32) -> Self {
		Flags { bits }
	}

	/// Returns a copy of the underlying number.
	#[inline(always)]
	pub fn bits(&self) -> u32 {
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
	///
	/// As the [`Flags`] struct uses `u32` under the hood, one can (in practice) set as many as `32` different bits, but some
	/// are reserved for internal use (ie the first 16 bits). However one can use the remaining 16 bits just fine, as seen in the example.
	/// Just using the `0b0000_0000_0000_0000` literal works because most platforms are little endian.
	/// On big-endian platforms, like ARM (raspberry PI and Apple Silicon), use the full `u32` literal (`0b0000_0000_0000_0000_0000_0000_0000_0000`), since the shorthand literal actually places bytes in the restricted range of bits.
	/// ```
	/// use vach::prelude::Flags;
	///
	/// let mut flag = Flags::from_bits(0b0000_0000_0000_0000);
	/// flag.set(0b0000_1000_0000_0000, true).unwrap();
	/// flag.set(0b1000_0000_0000_0000, true).unwrap();
	///
	/// assert_eq!(flag.bits(), 0b1000_1000_0000_0000);
	/// assert!(flag.contains(0b1000_0000_0000_0000));
	///
	/// // --------------------------v---------
	/// flag.set(0b0000_1000_0000_0001, false).unwrap(); // 0 flags remain zero
	/// assert_eq!(flag.bits(), 0b1000_0000_0000_0000);
	/// ```
	///
	/// ### Errors
	///  - Trying to set a bit in the forbidden section of the flags
	pub fn set(&mut self, bit: u32, toggle: bool) -> InternalResult<u32> {
		if Flags::_contains(Flags::RESERVED_MASK, bit) {
			return Err(InternalError::RestrictedFlagAccessError);
		} else {
			self.force_set(bit, toggle)
		}

		Ok(self.bits)
	}
	pub(crate) fn force_set(&mut self, mask: u32, toggle: bool) {
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
	/// flag.set(0b1000_0000_0000_0000, true).unwrap();
	/// assert!(flag.contains(0b1000_0000_0000_0000));
	/// ```
	pub fn contains(&self, bit: u32) -> bool {
		Flags::_contains(self.bits, bit)
	}

	// Auxillary function
	fn _contains(first: u32, other: u32) -> bool {
		(first & other) != 0
	}
}

#[rustfmt::skip]
impl fmt::Display for Flags {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let compressed = if self.contains(Flags::COMPRESSED_FLAG) { 'C' } else { '-' };
		let signed = if self.contains(Flags::SIGNED_FLAG) { 'S' } else { '-' };
		let encrypted = if self.contains(Flags::ENCRYPTED_FLAG) { 'E' } else { '-' };

		write!(f, "Flags[{}{}{}]", compressed, encrypted, signed)
	}
}

#[rustfmt::skip]
impl fmt::Debug for Flags {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let compressed = if self.contains(Flags::COMPRESSED_FLAG) { 'C' } else { '-' };
		let signed = if self.contains(Flags::SIGNED_FLAG) { 'S' } else { '-' };
		let encrypted = if self.contains(Flags::ENCRYPTED_FLAG) { 'E' } else { '-' };

		write!(
			f,
			"Flags[{}{}{}]: <{}u16 : {:#016b}>",
			compressed, encrypted, signed, self.bits, self.bits
		)
	}
}
