use std::io::{BufReader, Cursor, Seek, SeekFrom};
use crate::{loader::Archive, writer::ArchiveBuilder};

const FILE_1: &[u8] = include_bytes!("../../spec/main.txt");
const FILE_2: &[u8] = include_bytes!("../../Cargo.lock");

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

    let keypair = super::generate_keypair();
    let mut buffer= Cursor::new(Vec::new());

    builder.write_to(&mut buffer, &keypair).unwrap();
    
    buffer.seek(SeekFrom::Start(0));
    let mut archive = Archive::from_reader(BufReader::new(buffer), &keypair.public).unwrap();
    assert_eq!(archive.registry.entries[0].path, b"spec/main.txt");
    assert_eq!(archive.registry.entries[0].content_version, 1);
    assert_eq!(archive.registry.entries[0].mime_type, 2);    
    assert_eq!(FILE_1.len(), archive.get_file_at_index(0, &keypair.public).unwrap().len());

    assert_eq!(archive.registry.entries[1].path, b"Cargo.lock");
    assert_eq!(archive.registry.entries[1].content_version, 4);
    assert_eq!(archive.registry.entries[1].mime_type, 8);
    assert_eq!(FILE_2.len(), archive.get_file_at_index(1, &keypair.public).unwrap().len());
}