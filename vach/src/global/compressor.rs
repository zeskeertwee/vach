#![cfg(feature = "compression")]

use std::{
	fmt::Debug,
	io::{self, Read, Write},
};
use crate::prelude::Flags;

use super::{error::InternalError, result::InternalResult};

use lz4_flex as lz4;
use snap;
use brotli;

#[derive(Debug)]
/// Exported utility compressor used by `vach`
pub struct Compressor<T: Read> {
	data: T,
}

impl<'a, T: Read> Compressor<T> {
	/// Construct a new compressor over a read handle
	pub fn new(data: T) -> Compressor<T> {
		Compressor { data }
	}
	/// Pass in a compression algorithm to use, sit back and let the compressor do it's job
	pub fn compress(&mut self, algo: CompressionAlgorithm, output: &mut dyn Write) -> InternalResult<()> {
		match algo {
			CompressionAlgorithm::LZ4 => {
				let mut compressor = lz4::frame::FrameEncoder::new(output);
				io::copy(&mut self.data, &mut compressor)?;
				compressor.finish()?;

				Ok(())
			}
			CompressionAlgorithm::Snappy => {
				let mut compressor = snap::read::FrameEncoder::new(&mut self.data);
				io::copy(&mut compressor, output)?;

				Ok(())
			}
			CompressionAlgorithm::Brotli(quality) if quality < 12 && quality > 0 => {
				let mut compressor = brotli::CompressorReader::new(&mut self.data, 4096, quality, 21u32);
				io::copy(&mut compressor, output)?;

				Ok(())
			}
			CompressionAlgorithm::Brotli(_) => Err(InternalError::DeCompressionError(
				"Maximum Brotli compression level is 11 and minimum is 1".to_string(),
			)),
		}
	}
	/// Pass in a compression algorithm to use, sit back and let the decompressor do it's job. That is if the compressed data *is* compressed with the adjacent algorithm
	pub(crate) fn decompress(&mut self, algo: CompressionAlgorithm, output: &mut dyn Write) -> InternalResult<()> {
		match algo {
			CompressionAlgorithm::LZ4 => {
				let mut rdr = lz4::frame::FrameDecoder::new(&mut self.data);
				io::copy(&mut rdr, output)?;

				Ok(())
			}
			CompressionAlgorithm::Snappy => {
				let mut rdr = snap::read::FrameDecoder::new(&mut self.data);
				io::copy(&mut rdr, output)?;

				Ok(())
			}
			CompressionAlgorithm::Brotli(_) => {
				let mut rdr = brotli::Decompressor::new(&mut self.data, 4096);
				io::copy(&mut rdr, output)?;

				Ok(())
			}
		}
	}
}

/// Allows the user to specify which of three `Compression Algorithms` to use.
#[derive(Clone, Copy, Debug)]
pub enum CompressionAlgorithm {
	/// Uses [snappy](https://crates.io/crates/snap) for a well balanced compression experienced
	Snappy,
	/// Uses [LZ4](https://crates.io/crates/lz4_flex) for very fast decompression with average compression ratios
	LZ4,
	/// Uses [brotli](https://crates.io/crates/brotli) for higher compression ratios but *much* slower compression speed
	/// Allows one to specify the quality of the compression, from 1-11. (9 Recommended, 11 for extra compression)
	Brotli(u32),
}

impl From<CompressionAlgorithm> for u32 {
	fn from(algo: CompressionAlgorithm) -> Self {
		match algo {
			CompressionAlgorithm::Snappy => Flags::SNAPPY_COMPRESSED,
			CompressionAlgorithm::LZ4 => Flags::LZ4_COMPRESSED,
			CompressionAlgorithm::Brotli(_) => Flags::BROTLI_COMPRESSED,
		}
	}
}
