use ed25519_dalek::SIGNATURE_LENGTH;
use ed25519_dalek::{Signer, PublicKey, Verifier};
use signature::Signature;
use std::io::{Write, Read, Seek, SeekFrom};

const MAGIC_LENGTH: usize = 5;
const MAGIC_BYTES: &[u8; MAGIC_LENGTH] = b"VfACH";
const ARCHIVE_VERSION: u16 = 0;
const BASE_TABLE_ENTRY_SIZE: usize = 17 + SIGNATURE_LENGTH; // size of a FileTableEntry in bytes, not counting the path (since path can differ in size)

pub struct FileHeader {
    magic: [u8; MAGIC_LENGTH],
    archive_version: u16, // set by library to ensure correct file version
    content_version: u16, // set by user
    table_signature: [u8; SIGNATURE_LENGTH], // signs the table
    table_size: u16, // max 65536 'files' per file
    table: Vec<FileTableEntry>, // length equal to table_size
}

pub struct FileHeaderBuilder {
    content_version: u16,
    table: Vec<FileTableEntryBuilder>,
}

pub struct AchFile<R: Read + Seek> {
    archive_version: u16,
    content_version: u16,
    table: Vec<FileTableEntryRead>,
    reader: R,
}

#[derive(Clone, Debug)]
struct FileTableEntry {
    path_length: u8, // the path of the file, for example: geometry/wall.fbx, when this archive is mounted at /level_1, you would use the path /level_1/geometry/wall.fbx
    path: Vec<u8>, // length equal to path_length
    signature: [u8; SIGNATURE_LENGTH], // signature of the (compressed) blob
    uncompressed_size: u32, // the max size of the original file is 4GiB
    compressed_size: u32, // equal to uncompressed_size if not compressed
    offset: u64, // offset in bytes from the start of the file
}

#[derive(Debug)]
struct FileTableEntryRead {
    path: String,
    signature: [u8; SIGNATURE_LENGTH],
    uncompressed_size: u32,
    compressed_size: u32,
    offset: u64,
}

struct FileTableEntryBuilder {
    path: String,
    data: Vec<u8>,
}

impl FileHeader {
    pub const fn builder() -> FileHeaderBuilder {
        FileHeaderBuilder::new()
    }
}

impl FileTableEntry {
    fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<usize> {
        let mut written = 0;

        writer.write_all(&[self.path_length])?;
        writer.write_all(&self.path)?;
        writer.write_all(&self.uncompressed_size.to_le_bytes())?;
        writer.write_all(&self.compressed_size.to_le_bytes())?;
        writer.write_all(&self.signature)?;
        writer.write_all(&self.offset.to_le_bytes())?;

        written += BASE_TABLE_ENTRY_SIZE + self.path.len();

        Ok(written)
    }
}

impl FileHeaderBuilder {
    pub const fn new() -> Self {
        Self {
            content_version: 0,
            table: Vec::new(),
        }
    }

    pub fn set_content_version(&mut self, content_version: u16) {
        self.content_version = content_version;
    }

    /// The path for the file, in the virtual filesystem.
    /// For example, a file has path geometry/wall.fbx
    /// When this archive is mounted on `/level_1`, the path will become `/level_1/geometry/wall.fbx`
    pub fn add_file<P: ToString>(&mut self, path: P, data: Vec<u8>) {
        self.table.push(FileTableEntryBuilder {
            path: path.to_string(),
            data,
        })
    }

    pub fn write_to<W: Write + Seek, S: Signer<ed25519_dalek::Signature>>(self, writer: &mut W, signer: &S) -> std::io::Result<()> {
        let mut offset: usize = 0; // the location in the file as byte offset
        writer.write_all(MAGIC_BYTES)?;
        offset += MAGIC_LENGTH;
        writer.write_all(&ARCHIVE_VERSION.to_le_bytes())?;
        offset += 2;
        writer.write_all(&self.content_version.to_le_bytes())?;
        offset += 2;

        writer.write_all(&(self.table.len() as u16).to_le_bytes())?;
        offset += 2;

        // compensate for signature
        offset += SIGNATURE_LENGTH;
        
        let mut table_buf = std::io::Cursor::new(Vec::new()); // buffer for table because we sign it

        let mut data = Vec::new();
        let mut headers = Vec::new();
        for entry in self.table {
            let original_size = entry.data.len();
            let compressed_data = lz4_flex::compress(&entry.data);

            let processed_data = if compressed_data.len() < entry.data.len() {
                println!("Compressing {}, compressed size is {:.2}x original", entry.path, compressed_data.len() as f64 / original_size as f64);
                compressed_data
            } else {
                println!("Not compressing {}, compressed size is {:.2}x original", entry.path, compressed_data.len() as f64 / original_size as f64);
                entry.data
            };

            let data_signature = signer.sign(&processed_data);

            let header = FileTableEntry {
                path_length: entry.path.len() as u8,
                path: entry.path.to_owned().into_bytes(),
                uncompressed_size: original_size as u32,
                compressed_size: processed_data.len() as u32,
                signature: data_signature.to_bytes(),
                offset: 0,
            };

            headers.push(header);
            data.push(processed_data);
        }

        for header in headers.iter() {
            offset += BASE_TABLE_ENTRY_SIZE + header.path.len();
        }

        for (header, data) in headers.iter_mut().zip(&data) {
            header.offset = offset as u64;
            offset += data.len();
        }

        for header in headers.iter() {
            header.write_to(&mut table_buf)?;
        }

        // write signature to writer
        let signature = signer.sign(table_buf.get_ref());
        let signature_bytes = signature.as_bytes();
        
        if signature_bytes.len() != SIGNATURE_LENGTH {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Signature length does not match expected length!"));
        }
        writer.write_all(signature_bytes)?;
        writer.write_all(table_buf.get_ref())?;

        for data in data.iter() {
            writer.write_all(&data)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum AchError {
    InvalidMagic,
    Io(std::io::Error),
    FromUtfError(std::string::FromUtf8Error),
    InvalidSignature(signature::Error),
    InvalidTableSignature,
    DecompressError(lz4_flex::block::DecompressError)
}

impl From<std::io::Error> for AchError {
    fn from(other: std::io::Error) -> Self {
        Self::Io(other)
    }
}

impl<R: Read + Seek> AchFile<R> {
    pub fn read_from(mut reader: R, key: PublicKey) -> Result<Self, AchError> {
        let mut magic = [0u8; MAGIC_LENGTH];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC_BYTES {
            return Err(AchError::InvalidMagic);
        }

        let mut version_buf = [0u8; 4]; // used for reading archive_version and content_version
        reader.read_exact(&mut version_buf)?;
        let archive_version = u16::from_le_bytes([version_buf[0], version_buf[1]]);
        let content_version = u16::from_le_bytes([version_buf[2], version_buf[3]]);

        let mut table_size_buf = [0u8; 2];
        reader.read_exact(&mut table_size_buf)?;
        let table_size = u16::from_le_bytes(table_size_buf);

        let mut expected_table_signature_bytes = [0u8; SIGNATURE_LENGTH];
        reader.read_exact(&mut expected_table_signature_bytes)?;

        let mut table = Vec::new();
        let mut table_buf = Vec::new();

        for i in 0..table_size {
            let mut path_length = [0u8; 1];
            reader.read_exact(&mut path_length)?;

            // https://stackoverflow.com/questions/30412521/how-to-read-a-specific-number-of-bytes-from-a-stream
            let mut path_buf = vec![0u8; path_length[0] as usize];
            reader.read_exact(&mut path_buf)?;
            let path = String::from_utf8(path_buf.clone()).map_err(|e| AchError::FromUtfError(e))?;
            println!("Reading header for file {}", path);

            let mut size_buf = [0u8; 8];
            reader.read_exact(&mut size_buf)?;
            let uncompressed_size = u32::from_le_bytes([size_buf[0], size_buf[1], size_buf[2], size_buf[3]]);
            let compressed_size = u32::from_le_bytes([size_buf[4], size_buf[5], size_buf[6], size_buf[7]]);

            let mut blob_signature = [0u8; SIGNATURE_LENGTH];
            reader.read_exact(&mut blob_signature)?;

            let mut offset_buf = [0u8; 8];
            reader.read_exact(&mut offset_buf)?;
            let offset = u64::from_le_bytes(offset_buf);

            table_buf.extend_from_slice(&path_length);
            table_buf.extend_from_slice(&path_buf);
            table_buf.extend_from_slice(&size_buf);
            table_buf.extend_from_slice(&blob_signature);
            table_buf.extend_from_slice(&offset_buf);

            table.push(FileTableEntryRead {
                path,
                signature: blob_signature,
                uncompressed_size,
                compressed_size,
                offset
            });
        }

        let expected_table_signature: ed25519_dalek::Signature = Signature::from_bytes(&expected_table_signature_bytes).map_err(|e| AchError::InvalidSignature(e))?;
        if key.verify(&table_buf, &expected_table_signature).is_err() {
            return Err(AchError::InvalidTableSignature);
        } else {
            println!("Table signature OK");
        }

        Ok(AchFile {
            archive_version,
            content_version,
            table,
            reader,
        })
    }

    pub fn list_files(&self) {
        for file in self.table.iter() {
            let compressed = file.compressed_size != file.uncompressed_size;
            println!("{} is {}, and is {} bytes in the ach file", file.path, if compressed { "compressed" } else { "not compressed" }, file.compressed_size);
        }
    }

    pub fn read_file_at_index(&mut self, index: usize) -> Result<Vec<u8>, AchError> {
        let table_entry = &self.table[index];
        self.reader.seek(SeekFrom::Start(table_entry.offset))?;
        let mut blob_buf = vec![0u8; table_entry.compressed_size as usize];
        self.reader.read_exact(&mut blob_buf)?;

        if table_entry.compressed_size == table_entry.uncompressed_size {
            // uncompressed
            Ok(blob_buf)
        } else {
            // compressed
            lz4_flex::decompress(&blob_buf, table_entry.uncompressed_size as usize).map_err(|e| AchError::DecompressError(e))
        }
    }
}