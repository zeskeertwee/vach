#![allow(unused)]
use std::{
	fmt::{self, Debug},
	io::{self, Read, Write},
};
use crate::prelude::Flags;

use super::{error::InternalError, result::InternalResult};
use lz4_flex as lz4;

#[derive(Debug)]
pub struct Compressor<T: Read> {
	data: T,
}

impl<'a, T: Read> Compressor<T> {
	pub(crate) fn new(data: T) -> Compressor<T> {
		Compressor { data: data }
	}
	pub(crate) fn compress(&mut self, algo: CompressionAlgorithm) -> InternalResult<Vec<u8>> {
		match algo {
			CompressionAlgorithm::LZ4 => {
				let mut compressor = lz4::frame::FrameEncoder::new(vec![]);
				io::copy(&mut self.data, &mut compressor)?;

				Ok(compressor.finish()?)
			}
			CompressionAlgorithm::Snappy => todo!(),
			CompressionAlgorithm::Brotli => todo!(),
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
			CompressionAlgorithm::Snappy => todo!(),
			CompressionAlgorithm::Brotli => todo!(),
		}
	}
}

#[derive(Clone, Copy, Debug)]
pub enum CompressionAlgorithm {
	/// Uses [snappy](https://crates.io/crates/snap) for a well balanced compression experienced
	Snappy,
	/// Uses [LZ4](https://crates.io/crates/lz4_flex) for very fast decompression with average compression ratios
	LZ4,
	/// Uses [brotli](https://crates.io/crates/brotli) for higher compression ratios but *much* slower compression speed
	Brotli,
}

impl From<CompressionAlgorithm> for u32 {
	fn from(algo: CompressionAlgorithm) -> Self {
		match algo {
			CompressionAlgorithm::Snappy => Flags::SNAPPY_COMPRESSED,
			CompressionAlgorithm::LZ4 => Flags::LZ4_COMPRESSED,
			CompressionAlgorithm::Brotli => Flags::BROTLI_COMPRESSED,
		}
	}
}