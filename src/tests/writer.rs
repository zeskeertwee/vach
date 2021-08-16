use std::io::{BufReader, Cursor, Seek, SeekFrom};

use crate::{loader::Archive, writer::ArchiveBuilder};
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

const FILE_1: &[u8] = include_bytes!("../../spec/main.txt");
const FILE_2: &[u8] = include_bytes!("../../Cargo.lock");

fn generate_keypair() -> Keypair {
    let mut rng = OsRng {};
    Keypair::generate(&mut rng)
}

#[test]
fn archive_writing() {
    let mut builder = ArchiveBuilder::new();
    builder.add_file(
        FILE_1.to_owned(),
        "spec/main.txt",
        1,
        2,
    );

    builder.add_file(
        FILE_2.to_owned(),
        "Cargo.lock",
        4,
        8,
    );

    let keypair = generate_keypair();
    let mut buffer= Cursor::new(Vec::new());

    builder.write_to(&mut buffer, &keypair).unwrap();
    
    buffer.seek(SeekFrom::Start(0));
    let mut archive = Archive::from_reader(BufReader::new(buffer)).unwrap();
    assert_eq!(archive.registry.entries[0].path, b"spec/main.txt");
    assert_eq!(archive.registry.entries[0].content_version, 1);
    assert_eq!(archive.registry.entries[0].mime_type, 2);    
    assert_eq!(FILE_1.len(), archive.get_file_at_index(0).unwrap().len());

    assert_eq!(archive.registry.entries[1].path, b"Cargo.lock");
    assert_eq!(archive.registry.entries[1].content_version, 4);
    assert_eq!(archive.registry.entries[1].mime_type, 8);
    assert_eq!(FILE_2.len(), archive.get_file_at_index(1).unwrap().len());
}