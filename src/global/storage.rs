use std::fs::File;
#[derive(Debug)]
pub enum Storage {
    File(File),
    Vector(Vec<u8>)
}