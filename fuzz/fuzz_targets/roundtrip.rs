#![no_main]

use libfuzzer_sys::{arbitrary, fuzz_target};
use vach::{crypto_utils::gen_keypair, prelude::*};

#[derive(arbitrary::Arbitrary, Debug, Clone)]
struct ArbitraryVachInput {
	data: Vec<u8>,
	encrypt: bool,
	sign: bool,
	compress: u8,
	compression_algo: u8,
	brotli_compression_level: u8,
}

fn arbitrary_vach_input_to_leaf(
	key: &str,
	input: &ArbitraryVachInput,
) -> Leaf<std::io::Cursor<Vec<u8>>> {
	Leaf::new(std::io::Cursor::new(input.data.clone()), key)
		.encrypt(input.encrypt)
		.sign(input.sign)
		.compress(match input.compress % 3 {
			0 => CompressMode::Never,
			1 => CompressMode::Detect,
			2 => CompressMode::Always,
			_ => unreachable!(),
		})
		.compression_algo(match input.compression_algo % 3 {
			0 => CompressionAlgorithm::LZ4,
			1 => CompressionAlgorithm::Snappy,
			2 => CompressionAlgorithm::Brotli(((input.brotli_compression_level % 11) + 1) as u32),
			_ => unreachable!(),
		})
}

fuzz_target!(|data: (usize, std::collections::BTreeMap<String, ArbitraryVachInput>)| {
	let (builder_threads, data) = data;

	let generate_keypair = data.values().any(|input| input.encrypt || input.sign);
	let keypair = generate_keypair.then(gen_keypair);

	let mut leaves = data.iter().map(|(key, input)| arbitrary_vach_input_to_leaf(key, input)).collect::<Vec<_>>();
	let mut target = std::io::Cursor::new(Vec::new());

	dump(
		&mut target,
		&mut leaves,
		Some(BuilderConfig {
			num_threads: builder_threads % 8,
			flags: Flags::default(),
			signing_key: keypair.clone(),
		}),
		None,
	)
	.unwrap();

	let mut archive = match keypair {
		Some(kp) => Archive::with_key(target, &kp.verifying_key()).unwrap(),
		None => Archive::new(target).unwrap(),
	};

	let ids = archive.entries().keys().cloned().collect::<Vec<_>>();
	assert_eq!(ids.len(), leaves.len());

	for id in ids {
		let resource = archive.fetch_mut(&id).unwrap();

		let original_data = data.get(&*id).unwrap().data.as_slice();

		// assertions
		assert_eq!(resource.data.as_ref(), original_data);
		assert_eq!(resource.flags.contains(Flags::ENCRYPTED_FLAG), data.get(&*id).unwrap().encrypt);
		assert_eq!(resource.flags.contains(Flags::SIGNED_FLAG), data.get(&*id).unwrap().sign);

		match data.get(&*id).unwrap().compress % 3 {
			0 => assert!(!resource.flags.contains(Flags::COMPRESSED_FLAG)),
			1 => {}, // TODO: verify option 2?
			2 => assert!(resource.flags.contains(Flags::COMPRESSED_FLAG)),
			_ => unreachable!(),
		}

		// TODO: verify compression algorithm
	}
});
