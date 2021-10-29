use std::io::{self, Seek};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use vach::prelude::*;
use vach::utils::{gen_keypair, read_keypair};

// Remove io overhead by Sinking data into the void
struct Sink;

impl io::Seek for Sink {
	fn seek(&mut self, _: io::SeekFrom) -> io::Result<u64> {
		Ok(0)
	}
}

impl io::Write for Sink {
	fn write(&mut self, sequence: &[u8]) -> io::Result<usize> {
		Ok(sequence.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

pub fn criterion_benchmark(c: &mut Criterion) {
	const MAGIC: &[u8; 5] = b"BNCMK";
	let keypair = gen_keypair();

	c.bench_function("Builder::dump(---)", |b| {
		// Data to be written
		let data_1 = b"Around The World, Fatter wetter stronker" as &[u8];
		let data_2 = b"Imagine if this made sense" as &[u8];
		let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

		// Builder definition
		let keypair_bytes = keypair.to_bytes();
		let config = BuilderConfig::default()
			.magic(*MAGIC)
			.keypair(read_keypair(&keypair_bytes as &[u8]).unwrap());

		b.iter(|| {
			let mut builder = Builder::new();

			// Add data
			builder
				.add_leaf(
					Leaf::from_handle(data_1)
						.id("d1")
						.compress(CompressMode::Always),
				)
				.unwrap();
			builder
				.add_leaf(
					Leaf::from_handle(data_2)
						.id("d2")
						.compress(CompressMode::Never),
				)
				.unwrap();
			builder
				.add_leaf(
					Leaf::from_handle(data_3)
						.id("d3")
						.compress(CompressMode::Detect),
				)
				.unwrap();

			// Dump data
			builder.dump(black_box(Sink), &config).unwrap();
		});
	});

	c.bench_function("Archive::fetch(---)", |b| {
		const MAGIC: &[u8; 5] = b"CSDTD";
		let mut target = io::Cursor::new(Vec::<u8>::new());

		// Data to be written
		let data_1 = b"Around The World, Fatter wetter stronker" as &[u8];
		let data_2 = b"Imagine if this made sense" as &[u8];
		let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

		// Builder definition
		let keypair_bytes = gen_keypair().to_bytes();
		let config = BuilderConfig::default()
			.magic(*MAGIC)
			.keypair(read_keypair(&keypair_bytes as &[u8]).unwrap());
		let mut builder = Builder::new().template(Leaf::default().encrypt(true));

		// Add data
		builder
			.add_leaf(
				Leaf::from_handle(data_1)
					.id("d1")
					.compress(CompressMode::Always),
			)
			.unwrap();
		builder
			.add_leaf(
				Leaf::from_handle(data_2)
					.id("d2")
					.compress(CompressMode::Never),
			)
			.unwrap();
		builder
			.add_leaf(
				Leaf::from_handle(data_3)
					.id("d3")
					.compress(CompressMode::Detect),
			)
			.unwrap();

		// Dump data
		builder.dump(&mut target, &config).unwrap();

		// Load data
		target.seek(io::SeekFrom::Start(0)).unwrap();
		let mut config = HeaderConfig::default().magic(*MAGIC);
		config.load_public_key(&keypair_bytes[32..]).unwrap();

		let mut archive = Archive::with_config(&mut target, &config).unwrap();
		let mut sink = black_box(Sink);

		// Load data
		b.iter(|| {
			// Quick assertions
			let mut data = Vec::new();
			black_box(archive.fetch_write("d1", &mut sink).unwrap());
			black_box(archive.fetch_write("d2", &mut sink).unwrap());
			black_box(archive.fetch_write("d3", &mut data).unwrap());
			let string = String::from_utf8(data).unwrap();
			assert_eq!(String::from_utf8(data_3.to_vec()).unwrap(), string);
		});
	});
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
