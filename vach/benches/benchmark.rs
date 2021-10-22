use std::io;
use criterion::{criterion_group, criterion_main, Criterion};

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
	fn write(&mut self, _: &[u8]) -> io::Result<usize> {
		Ok(0)
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

		b.iter(|| -> anyhow::Result<()> {
			let mut builder = Builder::new();

			// Add data
			builder.add_leaf(
				Leaf::from_handle(data_1)
					.id("d1")
					.compress(CompressMode::Always),
			)?;
			builder.add_leaf(
				Leaf::from_handle(data_2)
					.id("d2")
					.compress(CompressMode::Never),
			)?;
			builder.add_leaf(
				Leaf::from_handle(data_3)
					.id("d3")
					.compress(CompressMode::Detect),
			)?;

			// Dump data
			builder.dump(Sink, &config)?;

			Ok(())
		});
	});

	c.bench_function("Archive::fetch(---)", |b| {
		// Builder definition
		let keypair_bytes = gen_keypair().to_bytes();
		let config = BuilderConfig::default()
			.magic(*MAGIC)
			.keypair(read_keypair(&keypair_bytes as &[u8]).unwrap());
		let mut builder = Builder::new().template(Leaf::default().compress(CompressMode::Always).encrypt(true));

		builder.add(b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8], "d1").unwrap();
		builder.add(b"Around The World, Fatter wetter stronker" as &[u8], "d2").unwrap();
		builder.add(b"Imagine if this made sense" as &[u8], "d3").unwrap();

		// Dump
		let mut target = io::Cursor::new(Vec::new());
		builder.dump(&mut target, &config).unwrap();
		let config = HeaderConfig::default().key(keypair.public);

		b.iter( || -> anyhow::Result<()> {
			let mut archive = Archive::with_config(&mut target, &config)?;

			dbg!(&archive.fetch("d1")?.data[0..12]);
			dbg!(&archive.fetch("d3")?.data[0..12]);
			dbg!(&archive.fetch("d2")?.data[0..12]);

			Ok(())
		})
	});
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
