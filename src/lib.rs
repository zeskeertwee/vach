#![allow(unused)]

pub(crate) mod loader;
pub(crate) mod writer;
pub(crate) mod global;

#[cfg(test)]
mod test {
    use crate::{global, loader};
    use std::{fs::File, io::{BufWriter, Write}};

    #[test]
    pub fn test_config() {
        let config = global::header::HeaderConfig::new(*b"VfACH", 0u16);
        let file = File::open("me.vach").unwrap();
        format!("{}", &config);

        let _header = global::header::Header::from_file(&file);
        loader::Archive::validate(&file, &config).unwrap();

        let _archive = loader::Archive::with_config(file, &global::header::HeaderConfig::default());
    }

	 #[test]
	 pub fn header_to_bytes() {
		  let file = File::open("me.vach").unwrap();
		  let header = global::header::Header::from_file(&file).unwrap();
	 }
    #[test]
    pub fn write_example_file() {
        let file = File::create("me.vach").unwrap();
        let mut writer = BufWriter::new(file);
		  {
			let header = global::header::Header::empty();
			writer.write(header.bytes().as_slice()).unwrap();
		  }
		  writer.flush().unwrap();
    }

	 #[test]
	 pub fn to_ne_bytes(){
		 let num = 514u16;
		 let array = num.to_ne_bytes();
		 assert_eq!(array, if cfg!(target_endian = "big") { num.to_be_bytes() } else { num.to_le_bytes() });

		 let array = [2u8, 2u8];
		 assert_eq!(num, u16::from_ne_bytes(array));
	 }
}
