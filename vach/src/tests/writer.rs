use std::io::{BufReader, Cursor, Seek, SeekFrom};
use crate::{loader::Archive, writer::ArchiveBuilder};

// this is complete gibberish
// generated with "dd if=/dev/urandom of=data.bin bs=1 count=1000000"
const FILE_1: &[u8] = include_bytes!("../../test-data/data.bin");
const FILE_1_PATH: &str = "data.bin";
const FILE_2: &[u8] = include_bytes!("../../test-data/lorem_ipsum.txt");
const FILE_2_PATH: &str = "lorem_ipsum.txt";

#[test]
fn archive_writing() {
    let mut builder = ArchiveBuilder::new();
    builder.add_file(
        FILE_1.to_owned(),
        FILE_1_PATH,
        1,
    );

    builder.add_file(
        FILE_2.to_owned(),
        FILE_2_PATH,
        4,
    );

    let keypair = super::generate_keypair();
    let mut buffer= Cursor::new(Vec::new());

    builder.write_to(&mut buffer, &keypair).unwrap();
    
    buffer.seek(SeekFrom::Start(0));
    let mut archive = Archive::from_reader(BufReader::new(buffer), &keypair.public).unwrap();
    assert_eq!(archive.registry.entries[0].path, FILE_1_PATH.as_bytes());
    assert_eq!(archive.registry.entries[0].content_version, 1);
    assert_eq!(FILE_1.len(), archive.get_file_at_index(0, &keypair.public).unwrap().len());

    assert_eq!(archive.registry.entries[1].path, FILE_2_PATH.as_bytes());
    assert_eq!(archive.registry.entries[1].content_version, 4);
    assert_eq!(FILE_2.len(), archive.get_file_at_index(1, &keypair.public).unwrap().len());
}