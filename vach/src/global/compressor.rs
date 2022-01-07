#![allow(unused)]
use std::{
	fmt::{self, Debug},
	io::{self, Read, Write},
};
use crate::prelude::Flags;

use super::{error::InternalError, result::InternalResult};

use lz4_flex as lz4;
use snap;
use brotli;

#[derive(Debug)]
pub struct Compressor<T: Read> {
	data: T,
}

impl<'a, T: Read> Compressor<T> {
	pub(crate) fn new(data: T) -> Compressor<T> {
		Compressor { data }
	}
	pub(crate) fn compress(&mut self, algo: CompressionAlgorithm) -> InternalResult<Vec<u8>> {
		match algo {
			CompressionAlgorithm::LZ4 => {
				let mut compressor = lz4::frame::FrameEncoder::new(vec![]);
				io::copy(&mut self.data, &mut compressor)?;

				compressor.flush()?;
				Ok(compressor.finish()?)
			}
			CompressionAlgorithm::Snappy => {
				let mut buffer = vec![];
				let mut compressor = snap::read::FrameEncoder::new(&mut self.data);

				compressor.read_to_end(&mut buffer);
				Ok(buffer)
			}
			CompressionAlgorithm::Brotli(quality) if quality < 12 && quality > 0 => {
				let mut buffer = vec![];
				let mut compressor =
					brotli::CompressorReader::new(&mut self.data, 4096, quality, 21u32);
				compressor.read_to_end(&mut buffer)?;

				Ok(buffer)
			}
			CompressionAlgorithm::Brotli(quality) => Err(InternalError::DeCompressionError(
				"Maximum Brotli compression level is 11 and minimum is 1".to_string(),
			)),
		}
	}
	pub(crate) fn decompress(&mut self, algo: CompressionAlgorithm) -> InternalResult<Vec<u8>> {
		match algo {
			CompressionAlgorithm::LZ4 => {
				let mut rdr = lz4::frame::FrameDecoder::new(&mut self.data);
				let mut buffer = vec![];

				rdr.read_to_end(&mut buffer)?;
				Ok(buffer)
			}
			CompressionAlgorithm::Snappy => {
				let mut rdr = snap::read::FrameDecoder::new(&mut self.data);
				let mut buffer = vec![];

				rdr.read_to_end(&mut buffer)?;
				Ok(buffer)
			}
			CompressionAlgorithm::Brotli(_) => {
				let mut rdr = brotli::Decompressor::new(&mut self.data, 4096);
				let mut buffer = vec![];

				rdr.read_to_end(&mut buffer)?;
				Ok(buffer)
			}
		}
	}
}

/// Allows a user to specify one of three `Compression Algorithm`s to use. Each with a specific use case
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
