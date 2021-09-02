use std::{fmt, fs::File, io::{BufReader, Read}, str};
use anyhow::bail;

pub const MAGIC_LENGTH: usize = 5;
pub const MAGIC: &'static [u8; MAGIC_LENGTH] = b"VfACH";

#[derive(Debug)]
pub struct Header {
    pub magic: [u8; MAGIC_LENGTH], // VfACH
    pub archive_version: u16,
    pub registry_size: u16,
}

impl Header {
    pub const SIZE: usize = MAGIC_LENGTH + 2 + 2 + ed25519_dalek::SIGNATURE_LENGTH;

    pub fn empty() -> Header {
        Header {
            magic: [0; MAGIC_LENGTH],
            archive_version: 0,
            registry_size: 0,
        }
    }

    /// attempt to read a header at the current stream position
    pub fn from_reader<R: Read>(reader: &mut BufReader<R>) -> anyhow::Result<Header> {
        // Construct header
        let mut header = Header::empty();

        // Read magic
        let mut buffer = [0; MAGIC_LENGTH];
        reader.read_exact(&mut buffer)?;
        header.magic = buffer;
        if &header.magic != MAGIC {
            bail!("Invalid magic in header: found {:?}, expected {:?}", header.magic, MAGIC);
        }

        // Read archive version and registry size, (u16, u16) from [u8; 4]
        let mut buffer = [0; 4];
        reader.read_exact(&mut buffer)?;
        header.archive_version = u16::from_le_bytes([buffer[0], buffer[1]]);
        header.registry_size = u16::from_le_bytes([buffer[2], buffer[3]]);

        reader.read_exact(&mut buffer)?;

        Result::Ok(header)
    }

    pub fn bytes(&self) -> Vec<u8> {
    	let mut buffer: Vec<u8> = Vec::new();
    	buffer.extend_from_slice(&self.magic);
    	buffer.extend_from_slice(&self.archive_version.to_le_bytes());
    	buffer.extend_from_slice(&self.registry_size.to_le_bytes());
    	buffer
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Archive Header] Version: {}, Magic: {}",
            5u32,
            str::from_utf8(&self.magic).unwrap()
        )
    }
}
