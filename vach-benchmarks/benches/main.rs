use std::collections::HashMap;
use std::io;
use criterion::{Criterion, black_box, criterion_group, criterion_main, Throughput};

use rayon::iter::{ParallelIterator, IntoParallelRefIterator};
use vach::prelude::*;
use vach::crypto_utils::gen_keypair;

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

	let mut h_config = ArchiveConfig::default().magic(*MAGIC);
	h_config.load_public_key(&keypair_bytes[32..]).unwrap();

	/* BUILDER BENCHMARKS */
	let mut builder_group = c.benchmark_group("Builder");

	let data_1 = b"Around The World, Fatter wetter stronker" as &[u8];
	let data_2 = b"Imagine if this made sense" as &[u8];
	let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

	// Configure benchmark
	builder_group.throughput(Throughput::Bytes((data_1.len() + data_2.len() + data_3.len()) as u64));

	builder_group.bench_function("Builder::dump(---)", |b| {
		b.iter(|| {
			let mut builder = Builder::new();

			// Add data
			builder
				.add_leaf(Leaf::from_handle(data_1).id("d1").compress(CompressMode::Always))
				.unwrap();
			builder
				.add_leaf(Leaf::from_handle(data_2).id("d2").compress(CompressMode::Never))
				.unwrap();
			builder
				.add_leaf(Leaf::from_handle(data_3).id("d3").compress(CompressMode::Detect))
				.unwrap();

			// Dump data
			builder.dump(Sink::new(), &b_config).unwrap();
		});
	});

	// Drop Builder group
	drop(builder_group);

	/* ARCHIVE BENCHMARKS */
	let mut throughput_group = c.benchmark_group("Loader");
	let mut target = io::Cursor::new(Vec::<u8>::new());

	{
		// Builds an archive source from which to benchmark
		let template = Leaf::default()
			.encrypt(false)
			.sign(false)
			.compress(CompressMode::Never)
			.compression_algo(CompressionAlgorithm::LZ4);
		let mut builder = Builder::new().template(template);

		// Add data
		builder.add(data_1, "d1").unwrap();
		builder.add(data_2, "d2").unwrap();
		builder.add(data_3, "d3").unwrap();

		// Dump data
		builder.dump(&mut target, &b_config).unwrap();
	}

	// Load data
	throughput_group.throughput(Throughput::Bytes((data_1.len() + data_2.len() + data_3.len()) as u64));

	let archive = Archive::with_config(&mut target, &h_config).unwrap();
	let mut sink = Sink::new();

	throughput_group.bench_function("Archive::fetch_write(---)", |b| {
		// Load data
		b.iter(|| {
			archive.fetch_write("d1", &mut sink).unwrap();
			archive.fetch_write("d2", &mut sink).unwrap();
			archive.fetch_write("d3", &mut sink).unwrap();
		});
	});

	throughput_group.bench_function("Archive::fetch_batch(---)", |b| {
		// Load data
		b.iter(|| {
			let resources = ["d2", "d1", "d3"]
				.as_slice()
				.par_iter()
				.map(|id| (id, archive.fetch(&id)))
				.collect::<HashMap<_, _>>();

			criterion::black_box(resources)
		});
	});

	drop(throughput_group);

	c.bench_function("Archive::LOAD_NEW", |b| {
		// How fast it takes to load a new archive
		b.iter(|| {
			Archive::with_config(&mut target, &h_config).unwrap();
		})
	});
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
