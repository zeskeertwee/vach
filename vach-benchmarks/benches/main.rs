use std::io::{self, Seek};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use vach::prelude::*;
use vach::utils::gen_keypair;

// Remove io overhead by Sinking data into the void
struct Sink;

impl Sink {
	fn new() -> Sink {
		black_box(Sink)
	}
}

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
	let keypair_bytes = &gen_keypair().to_bytes() as &[u8];

	let mut b_config = BuilderConfig::default().magic(*MAGIC);
	b_config.load_keypair(keypair_bytes).unwrap();

	let mut h_config = HeaderConfig::default().magic(*MAGIC);
	h_config.load_public_key(&keypair_bytes[32..]).unwrap();

	/* BUILDER::DUMP(---) BENCHMARKS */
	let data_1 = b"Around The World, Fatter wetter stronker" as &[u8];
	let data_2 = b"Imagine if this made sense" as &[u8];
	let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

	c.bench_function("Builder::dump(---)", |b| {
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
			builder.dump(Sink::new(), &b_config).unwrap();
		});
	});

	/* ARCHIVE::FETCH(---) BENCHMARKS */
	let mut target = io::Cursor::new(Vec::<u8>::new());
	let template = Leaf::default()
		.encrypt(true)
		.sign(false)
		.compress(CompressMode::Detect);

	{
		let mut builder = Builder::new().template(template);

		// Add data
		builder.add(data_1, "d1").unwrap();
		builder.add(data_2, "d2").unwrap();
		builder.add(data_3, "d3").unwrap();

		// Dump data
		builder.dump(&mut target, &b_config).unwrap();
	}

	// Load data
	target.seek(io::SeekFrom::Start(0)).unwrap();

	let mut archive = Archive::with_config(&mut target, &h_config).unwrap();
	let mut sink = Sink::new();

	c.bench_function("Archive::fetch(---)", |b| {
		// Load data
		b.iter(|| {
			// Quick assertions
			let mut data = Vec::new();

			archive.fetch_write("d1", &mut sink).unwrap();
			archive.fetch_write("d2", &mut sink).unwrap();
			archive.fetch_write("d3", &mut data).unwrap();

			let string = String::from_utf8(data).unwrap();
			assert_eq!(String::from_utf8(data_3.to_vec()).unwrap(), string);
		});
	});
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
