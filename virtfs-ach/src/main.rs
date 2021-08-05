use virtfs_ach::AchFile;
use virtfs_ach::FileHeader;
use std::fs::File;
use ed25519_dalek::{Keypair, SecretKey, PublicKey};
use rand::rngs::OsRng;
use std::io::Write;

const DATA: &[u8] = include_bytes!("../test-data/data.txt");
const PUB_BYTES: &[u8] = include_bytes!("../test-data/key.pub");
const PRV_BYTES: &[u8] = include_bytes!("../test-data/key.prv");
const ACH_BYTES: &[u8] = include_bytes!("../test-data/test.ach");

fn main() {
    // let keypair = build_keypair();
    // let mut builder = FileHeader::builder();
    // builder.set_content_version(0);
    // builder.add_file("data/text.txt", DATA.to_owned());
    // let mut file = File::create("./test.ach").unwrap();
    // builder.write_to(&mut file, &keypair).unwrap();


    let keypair = build_keypair();
    let mut data = std::io::Cursor::new(ACH_BYTES);
    let mut ach = AchFile::read_from(&mut data, keypair.public).unwrap();
    let data = ach.read_file_at_index(0).unwrap();
    println!("{}", String::from_utf8(data).unwrap());
}

fn build_keypair() -> Keypair {
    let pub_key = PublicKey::from_bytes(PUB_BYTES).unwrap();
    let prv_key = SecretKey::from_bytes(PRV_BYTES).unwrap();
    Keypair {
        public: pub_key,
        secret: prv_key,
    }
}

fn generate_keypair() {
    let mut rng = OsRng {};
    let keypair = Keypair::generate(&mut rng);
    let pub_key = keypair.public.to_bytes();
    let priv_key = keypair.secret.to_bytes();

    let mut pub_file = File::create("./key.pub").unwrap();
    let mut priv_file = File::create("./key.prv").unwrap();

    pub_file.write_all(&pub_key).unwrap();
    priv_file.write_all(&priv_key).unwrap();
}