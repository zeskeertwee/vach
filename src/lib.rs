pub(crate) mod loader;
pub(crate) mod writer;

#[cfg(test)]
mod test {
    use crate::loader;
    use std::{fs::File, io::{BufWriter, Write}};

    #[test]
    pub fn test_config() {
        let config = loader::header::Config::new(*b"VfACH", 0u16);
        let file = File::open("me.vach").unwrap();
        println!("{}", &config);

        let _header = loader::header::Header::from_file(&file, &false);
        loader::Archive::validate(&file, &config).unwrap();

        let _archive = loader::Archive::with_config(file, &loader::header::Config::default());
    }

    #[test]
    pub fn write_example_file() {
        let file = File::create("me.vach").unwrap();
        let mut writer = BufWriter::new(file);
        writer.write(b"VfACH").unwrap(); // MAGIC
        writer.write(&[2; 4]).unwrap(); // FLAGS
        writer.write(&[4; 2]).unwrap(); // VERSION
        writer.write(&[6; 2]).unwrap(); // ENTRIES
    }
}
