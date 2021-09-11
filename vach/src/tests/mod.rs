mod global;
mod writer;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use std::sync::Once;

static INIT_LOG: Once = Once::new();

fn init_log() {
    INIT_LOG.call_once(|| {
        if !std::env::var("RUST_LOG").is_ok() {
            std::env::set_var("RUST_LOG", "trace");
        }

        pretty_env_logger::init();
    });
}

fn generate_keypair() -> Keypair {
    let mut rng = OsRng {};
    Keypair::generate(&mut rng)
}