

trait FileSystem {
	fn parse_from_binary() {}
	fn fetch_resource() { unimplemented!() }
	fn delete_resource() { unimplemented!() }
	fn write_to_file() { unimplemented!() }
}



// Basically data obtained from the archive
#[derive(Debug)]
struct ArchiveData {
    // INFO: Supports 65535 mime types which is more than enough
    mime_type: u16,
    data: Box<[u8]>,
}

impl fmt::Display for ArchiveData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[ArchiveEntry] mime_type: {m_type}, size: {length}",
            m_type = self.mime_type,
            length = self.data.len()
        )
    }
}

trait Parse {
	 fn parse_from_location() {}
}
