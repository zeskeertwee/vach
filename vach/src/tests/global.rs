use ed25519_dalek::{Signer, Keypair};
use std::io::{Cursor, BufReader};
use crate::global::{
    header::{
        MAGIC_LENGTH,
        MAGIC,
        Header
    },
    registry::{
        Registry,
        RegistryEntry,
        RegistryEntryFlags
    }
};

const HED_ARCHIVE_VERSION: u16 = u16::from_le_bytes([0x01, 0x02]);
const HED_REGISTRY_SIZE: u16 = u16::from_le_bytes([0x01, 0x03]);
const REG_FLAGS: u8 = RegistryEntryFlags::IS_COMPRESSED.bits();
const REG_CONTENT_VERSION: u16 = u16::from_le_bytes([0x27, 0x72]);
const REG_PATH_NAME_LENGTH: u16 = 265;
const REG_PATH: [u8; REG_PATH_NAME_LENGTH as usize] = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur pretium, lectus non pretium mattis, ex ex auctor elit, pellentesque pharetra nunc orci vitae eros. Curabitur massa lectus, aliquet non ex eu, venenatis euismod dolor. Maecenas cursus ipsum ac justo.";
const REG_COMPRESSED_SIZE: u32 = u32::from_le_bytes([0x01, 0x02, 0x03, 0x04]);
const REG_BYTE_OFFSET: u64 = u64::from_le_bytes([0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);

fn generate_registry_entry() -> Vec<u8> {
    let mut buffer = Vec::new();

    buffer.push(REG_FLAGS);
    buffer.extend_from_slice(&REG_CONTENT_VERSION.to_le_bytes());
    buffer.extend_from_slice(&[0; ed25519_dalek::SIGNATURE_LENGTH]);
    buffer.extend_from_slice(&REG_PATH_NAME_LENGTH.to_le_bytes());
    buffer.extend_from_slice(&REG_PATH);
    buffer.extend_from_slice(&REG_COMPRESSED_SIZE.to_le_bytes());
    buffer.extend_from_slice(&REG_BYTE_OFFSET.to_le_bytes());

    buffer
}

fn generate_header() -> Vec<u8> {
    let mut buffer = Vec::new();

    buffer.extend_from_slice(MAGIC);
    buffer.extend_from_slice(&HED_ARCHIVE_VERSION.to_le_bytes());
    buffer.extend_from_slice(&HED_REGISTRY_SIZE.to_le_bytes());

    buffer
}

#[test]
fn registry_entry_serialization() {
    super::init_log();

    let registry_entry_buffer = generate_registry_entry();

    let entry = RegistryEntry::from_reader(&mut BufReader::new(Cursor::new(&registry_entry_buffer))).unwrap();
    assert_eq!(entry.flags.bits(), REG_FLAGS);
    assert_eq!(entry.content_version, REG_CONTENT_VERSION);
    assert_eq!(entry.blob_signature, [0_u8; ed25519_dalek::SIGNATURE_LENGTH]);
    assert_eq!(entry.path_name_length, REG_PATH_NAME_LENGTH);
    assert_eq!(entry.path, REG_PATH);
    assert_eq!(entry.compressed_size, REG_COMPRESSED_SIZE);
    assert_eq!(entry.byte_offset, REG_BYTE_OFFSET);

    assert_eq!(entry.bytes(), registry_entry_buffer);
}

#[test]
fn registry_and_header_serialization() {
    super::init_log();

    let mut registry = Vec::new();
    
    for i in 0..HED_REGISTRY_SIZE {
        registry.extend_from_slice(&generate_registry_entry());
    }
    
    assert_eq!(registry.len(), HED_REGISTRY_SIZE as usize * generate_registry_entry().len());
    let mut header_buffer = generate_header();
    header_buffer.extend_from_slice(&registry);

    let mut reader = BufReader::new(Cursor::new(header_buffer));

    let header = Header::from_reader(&mut reader).unwrap();
    let registry = Registry::from_reader(&mut reader, &header);
}

#[test]
fn registry_entry_length() {
    super::init_log();

    let mut registry_entry = RegistryEntry::empty();
    registry_entry.path = REG_PATH.to_vec();
    registry_entry.path_name_length = REG_PATH_NAME_LENGTH;

    assert_eq!(registry_entry.bytes().len(), registry_entry.size());
}

#[test]
fn header_size() {
    super::init_log();

    let header = Header::empty();

    assert_eq!(header.bytes().len(), Header::SIZE);
}