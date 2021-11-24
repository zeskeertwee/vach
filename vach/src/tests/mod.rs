// This is meant to mirror as closely as possible, how users should use the crate

#![cfg(test)]
// Boring, average every day contemporary imports
use std::{
	fs::File,
	io::{Seek, SeekFrom},
	str,
};

use crate::{global::result::InternalResult, prelude::*};

// Contains both the public key and secret key in the same file:
// secret -> [u8; crate::SECRET_KEY_LENGTH], public -> [u8; crate::PUBLIC_KEY_LENGTH]
const KEYPAIR: &str = "test_data/pair.pub";

// The paths to the Archives, to be written|loaded
const SIGNED_TARGET: &str = "test_data/signed/target.vach";
const SIMPLE_TARGET: &str = "test_data/simple/target.vach";
const ENCRYPTED_TARGET: &str = "test_data/encrypted/target.vach";

// Custom bitflag tests
const CUSTOM_FLAG_1: u16 = 0b_0000_1000_0000_0000;
const CUSTOM_FLAG_2: u16 = 0b_0000_0100_0000_0000;
const CUSTOM_FLAG_3: u16 = 0b_0000_0000_1000_0000;
const CUSTOM_FLAG_4: u16 = 0b_0000_0000_0001_0000;

#[test]
fn custom_bitflags() -> InternalResult<()> {
	let target = File::open(SIMPLE_TARGET)?;
	let archive = Archive::from_handle(target)?;
	let entry = archive.fetch_entry("poem").unwrap();
	let flags = Flags::from_bits(entry.flags.bits());
	assert_eq!(flags.bits(), entry.flags.bits());
	assert!(flags.contains(CUSTOM_FLAG_1 | CUSTOM_FLAG_2 | CUSTOM_FLAG_3 | CUSTOM_FLAG_4));

	Ok(())
}

#[test]
fn flag_restricted_access() {
	let mut flag = Flags::from_bits(0b1111_1000_0000_0000);

	// This should return an error
	if let Err(error) = flag.set(Flags::COMPRESSED_FLAG, true) {
		assert_eq!(error, InternalError::RestrictedFlagAccessError);
	} else {
		panic!("Access to restricted flags has been allowed, this should not be feasible")
	};
}

#[test]
fn flags_set_intersects() {
	let mut flag = Flags::empty();

	flag.force_set(Flags::COMPRESSED_FLAG, true);
	assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG);

	flag.force_set(Flags::COMPRESSED_FLAG, true);
	assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG);

	flag.force_set(Flags::SIGNED_FLAG, true);
	assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG | Flags::SIGNED_FLAG);

	flag.force_set(Flags::COMPRESSED_FLAG, false);
	assert_eq!(flag.bits(), Flags::SIGNED_FLAG);

	flag.force_set(Flags::COMPRESSED_FLAG, false);
	assert_eq!(flag.bits(), Flags::SIGNED_FLAG);

	flag.force_set(Flags::COMPRESSED_FLAG | Flags::SIGNED_FLAG, true);
	assert_eq!(flag.bits(), Flags::COMPRESSED_FLAG | Flags::SIGNED_FLAG);
}

#[test]
fn defaults() {
	// The reason we are pulling the header directly from global namespace is because it's not exposed to the public API
	// We still need to conduct tests on them tho.
	use crate::global::header::Header;

	let _header_config = HeaderConfig::default();
	let _header = Header::default();
	let _registry_entry = RegistryEntry::empty();
	let _resource = Resource::default();
	let _leaf = Leaf::default();
	let _builder = Builder::new();
	let _builder_config = BuilderConfig::default();
	let _flags = Flags::default();
}

#[test]
fn header_config() -> InternalResult<()> {
	// `Header` is a private struct, ie pub(crate). So we need to grab it manually
	use crate::global::header::Header;

	let config = HeaderConfig::new(*b"VfACH", None);
	let mut file = File::open("test_data/simple/target.vach")?;
	println!("{}", &config);

	let header = Header::from_handle(&mut file)?;
	println!("{}", header);

	Header::validate(&header, &config)?;
	Ok(())
}

#[test]
fn builder_no_signature() -> InternalResult<()> {
	let mut builder = Builder::default();
	let build_config = BuilderConfig::default();

	builder.add(File::open("test_data/song.txt")?, "song")?;
	builder.add(File::open("test_data/lorem.txt")?, "lorem")?;
	builder.add(File::open("test_data/bee.script")?, "script")?;
	builder.add(File::open("test_data/quicksort.wasm")?, "wasm")?;

	let mut poem_flags = Flags::default();
	poem_flags.set(
		CUSTOM_FLAG_1 | CUSTOM_FLAG_2 | CUSTOM_FLAG_3 | CUSTOM_FLAG_4,
		true,
	)?;

	builder.add_leaf(
		Leaf::from_handle(File::open("test_data/poem.txt")?)
			.compress(CompressMode::Always)
			.version(10)
			.id("poem")
			.flags(poem_flags),
	)?;

	builder.add_leaf(
		Leaf::from_handle(b"Hello, Cassandra!" as &[u8])
			.compress(CompressMode::Never)
			.id("greeting"),
	)?;

	let mut target = File::create(SIMPLE_TARGET)?;
	builder.dump(&mut target, &build_config)?;

	Ok(())
}

#[test]
fn fetch_no_signature() -> InternalResult<()> {
	let target = File::open(SIMPLE_TARGET)?;
	let mut archive = Archive::from_handle(target)?;
	dbg!(archive.entries());
	let resource = archive.fetch("poem")?;

	// Windows bullshit
	#[cfg(target_os = "windows")]
	{
		assert_eq!(resource.data.len(), 359);
	}
	#[cfg(not(any(target_os = "windows", target_os = "ios")))]
	{
		assert_eq!(resource.data.len(), 345);
	}

	assert!(!resource.secured);
	assert!(resource.flags.contains(Flags::COMPRESSED_FLAG));

	println!("{}", String::from_utf8(resource.data).unwrap());

	let hello = archive.fetch("greeting")?;
	assert_eq!("Hello, Cassandra!", String::from_utf8(hello.data).unwrap());
	assert!(!hello.flags.contains(Flags::COMPRESSED_FLAG));

	Ok(())
}

#[test]
fn gen_keypair() -> InternalResult<()> {
	use crate::utils::gen_keypair;

	// NOTE: regenerating new keys will break some tests
	let regenerate = false;

	if regenerate {
		let keypair = gen_keypair();

		std::fs::write(KEYPAIR, &keypair.to_bytes())?;
	};

	Ok(())
}

#[test]
fn builder_with_signature() -> InternalResult<()> {
	let mut builder = Builder::default();

	let mut build_config = BuilderConfig::default().callback(Box::new(|_, _, d| {
		dbg!(&d);
	}));
	build_config.load_keypair(File::open(KEYPAIR)?)?;

	builder.add_dir(
		"test_data",
		Some(&Leaf::default().compress(CompressMode::Detect).sign(true)),
	)?;

	// Tests conditional signing
	builder.add_leaf(Leaf::default().id("not_signed").sign(false))?;

	let mut target = File::create(SIGNED_TARGET)?;
	println!(
		"Number of bytes written: {}, into signed archive.",
		builder.dump(&mut target, &build_config)?
	);

	Ok(())
}

#[test]
fn fetch_with_signature() -> InternalResult<()> {
	let target = File::open(SIGNED_TARGET)?;

	// Load keypair
	let mut config = HeaderConfig::default();
	let mut keypair = File::open(KEYPAIR)?;
	keypair.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
	config.load_public_key(keypair)?;

	let mut archive = Archive::with_config(target, &config)?;
	let resource = archive.fetch("test_data/song.txt")?;
	let song = str::from_utf8(resource.data.as_slice()).unwrap();

	// The adjacent resource was flagged to not be signed
	let not_signed_resource = archive.fetch("not_signed")?;
	assert!(!not_signed_resource.flags.contains(Flags::SIGNED_FLAG));
	assert!(!not_signed_resource.secured);

	// The adjacent resource was flagged to not be signed
	let not_signed_resource = archive.fetch("not_signed")?;
	assert!(!not_signed_resource.flags.contains(Flags::SIGNED_FLAG));
	assert!(!not_signed_resource.secured);

	// Check identity of retrieved data
	println!("{}", song);

	// Windows bullshit
	#[cfg(target_os = "windows")]
	{
		assert_eq!(song.len(), 2041);
	}
	#[cfg(not(any(target_os = "windows", target_os = "ios")))]
	{
		assert_eq!(song.len(), 1977);
	}

	assert!(resource.secured);
	assert!(resource.flags.contains(Flags::SIGNED_FLAG));

	Ok(())
}

#[test]
fn fetch_write_with_signature() -> InternalResult<()> {
	let target = File::open(SIGNED_TARGET)?;

	// Load keypair
	let mut config = HeaderConfig::default();
	let mut keypair = File::open(KEYPAIR)?;
	keypair.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
	config.load_public_key(keypair)?;

	let mut archive = Archive::with_config(target, &config)?;
	let mut song = Vec::new();

	let metadata = archive.fetch_write("test_data/poem.txt", &mut song)?;
	assert!(metadata.2);
	assert!(metadata.0.contains(Flags::SIGNED_FLAG));

	// Windows bullshit
	#[cfg(target_os = "windows")]
	{
		assert_eq!(song.len(), 359);
	}
	#[cfg(not(any(target_os = "windows", target_os = "ios")))]
	{
		assert_eq!(song.len(), 345);
	}

	// Assert identity of retrieved data
	println!("{}", String::from_utf8(song).unwrap());

	Ok(())
}

#[test]
fn edcryptor_test() -> InternalResult<()> {
	use crate::utils::gen_keypair;
	use crate::global::edcryptor::EDCryptor;

	let pk = gen_keypair().public;

	let crypt = EDCryptor::new(&pk, *crate::DEFAULT_MAGIC);

	let data = vec![12, 12, 12, 12];

	let ciphertext = crypt.encrypt(&data).unwrap();
	let plaintext = crypt.decrypt(&ciphertext).unwrap();

	assert_ne!(&plaintext, &ciphertext);
	assert_eq!(&plaintext, &data);
	Ok(())
}

#[test]
fn builder_with_encryption() -> InternalResult<()> {
	let mut builder = Builder::new().template(
		Leaf::default()
			.encrypt(true)
			.compress(CompressMode::Never)
			.sign(true),
	);

	let mut build_config = BuilderConfig::default();
	build_config.load_keypair(File::open(KEYPAIR)?)?;

	builder.add_dir("test_data", None)?;

	let mut target = File::create(ENCRYPTED_TARGET)?;
	println!(
		"Number of bytes written: {}, into encrypted and fully compressed archive.",
		builder.dump(&mut target, &build_config)?
	);

	Ok(())
}

#[test]
fn fetch_from_encrypted() -> InternalResult<()> {
	let target = File::open(ENCRYPTED_TARGET)?;

	// Load keypair
	let mut config = HeaderConfig::default();
	let mut public_key = File::open(KEYPAIR)?;
	public_key.seek(SeekFrom::Start(crate::SECRET_KEY_LENGTH as u64))?;
	config.load_public_key(public_key)?;

	let mut archive = Archive::with_config(target, &config)?;
	let resource = archive.fetch("test_data/song.txt")?;
	let song = str::from_utf8(resource.data.as_slice()).unwrap();

	// Check identity of retrieved data
	println!("{}", song);

	// Windows bullshit
	#[cfg(target_os = "windows")]
	{
		assert_eq!(song.len(), 2041);
	}
	#[cfg(not(any(target_os = "windows", target_os = "ios")))]
	{
		assert_eq!(song.len(), 1977);
	}

	assert!(resource.secured);
	assert!(!resource.flags.contains(Flags::COMPRESSED_FLAG));
	assert!(resource.flags.contains(Flags::ENCRYPTED_FLAG));

	Ok(())
}

#[test]
fn cyclic_linked_leafs() {
	use std::io::Cursor;

	// init
	let mut target = Cursor::new(Vec::<u8>::new());

	// Builder stage
	let mut builder = Builder::default();

	builder
		.add_leaf(
			Leaf::default()
				.id("d2_link")
				.link_mode(Some("d1_link".to_string())),
		)
		.unwrap();
	builder
		.add_leaf(
			Leaf::default()
				.id("d1_link")
				.link_mode(Some("d2_link".to_string())),
		)
		.unwrap();
	builder
		.dump(&mut target, &BuilderConfig::default())
		.unwrap();

	target.seek(SeekFrom::Start(0)).unwrap();
	let mut archive = Archive::from_handle(target).unwrap();

	// Assert that this causes an error, [Cyclic Linked Leafs]
	if let Err(err) = archive.fetch("d1_link") {
		match err {
			InternalError::CyclicLinkReferenceError(_, _) => (),
			_ => panic!("Unrecognized error. Expected cyclic linked leaf error"),
		}
	};
}

#[test]
fn consolidated_example() -> InternalResult<()> {
	use crate::utils::{gen_keypair, read_keypair};
	use std::{io::Cursor, time::Instant};

	const MAGIC: &[u8; 5] = b"CSDTD";
	let mut target = Cursor::new(Vec::<u8>::new());

	// Data to be written
	let data_1 = b"Around The World, Fatter wetter stronker" as &[u8];
	let data_2 = b"Imagine if this made sense" as &[u8];
	let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

	// Builder definition
	let keypair_bytes = gen_keypair().to_bytes();
	let config = BuilderConfig::default()
		.magic(*MAGIC)
		.keypair(read_keypair(&keypair_bytes as &[u8])?);
	let mut builder = Builder::new().template(Leaf::default().encrypt(true));

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
	builder.add_leaf(
		Leaf::default()
			.id("d3_link")
			.link_mode(Some("d3".to_string())),
	)?;

	// Dump data
	let then = Instant::now();
	builder.dump(&mut target, &config)?;

	// Just because
	println!("Building took: {}us", then.elapsed().as_micros());

	// Ensure your stream_position is where you want it to be, so here at the start of the Cursor (0)
	target.seek(SeekFrom::Start(0))?;

	// Load data
	let mut config = HeaderConfig::default().magic(*MAGIC);
	config.load_public_key(&keypair_bytes[32..])?;

	let mut archive = Archive::with_config(target, &config)?;

	// Quick assertions
	let then = Instant::now();
	assert_eq!(archive.fetch("d1")?.data.as_slice(), data_1);
	assert_eq!(archive.fetch("d2")?.data.as_slice(), data_2);
	assert_eq!(archive.fetch("d3")?.data.as_slice(), data_3);
	assert_eq!(archive.fetch("d3_link")?.data.as_slice(), data_3);

	println!("Fetching took: {}us", then.elapsed().as_micros());

	// All seems ok
	Ok(())
}
