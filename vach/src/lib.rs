#![allow(clippy::or_fun_call)]
#![allow(clippy::manual_map)]
#![deny(missing_docs)]

/*!
<p align="center">
  <img src="https://raw.githubusercontent.com/zeskeertwee/virtfs-rs/main/media/logo.png" alt=".vach logo" width="180" height="180">
</p>
<p align=center> A simple archiving format, designed for storing assets in compact secure containers </p>
<p align=center>
  <a href="https://docs.rs/vach"><img alt="docs.rs" src="https://img.shields.io/docsrs/vach?style=flat-square"></a>
  <a href="https://github.com/zeskeertwee/virtfs-rs/blob/main/LICENSE"><img alt="GitHub" src="https://img.shields.io/github/license/zeskeertwee/vach?style=flat-square"></a>
  <a href="https://github.com/zeskeertwee/virtfs-rs/blob/main/LICENSE"><img alt="LICENSE: MIT" src="https://img.shields.io/crates/l/vach?style=flat-square"></a>
  <a href="https://github.com/zeskeertwee/virtfs-rs/actions/workflows/rust.yml"><img alt="GitHub Build and Test actions" src="https://github.com/zeskeertwee/virtfs-rs/workflows/Rust/badge.svg"></a>
  <a href="https://github.com/zeskeertwee/virtfs-rs/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/zeskeertwee/virtfs-rs?style=flat-square"></a>
</p>
<p align=center>
 <a href="https://docs.rs/vach">Docs</a> | <a href="https://github.com/zeskeertwee/virtfs-rs">Repo</a>
</p>

---

`vach`, pronounced like "puck" but with a "v", is a archiving and resource transmission format. It was built to be secure, contained and protected. It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. `vach` also has in-built support for multiple compression schemes (LZ4, Snappy and Brolti), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/0.1.5/vach/prelude/struct.Flags.html#), [encryption](https://crates.io/crates/aes-gcm-siv/0.10.3) and some degree of archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/virtfs-rs/blob/main/spec/main.txt)**. Any and *all* help will be much appreciated, especially proof reading the docs and code review.

### 👄 Terminologies

- **Archive:** Any source of data, for example a file or TCP stream, that is a valid `vach` data source.
- **Leaf:** Any actual data endpoint within an archive, what `tar` calls archive members, for example `footstep1.wav` in `sounds.vach`.
- **Entry:** Some data in the registry section of a `vach` source on an corresponding [leaf](crate::builder::Leaf). For example, `{ id: footstep.wav, location: 45, offset: 2345, flags: 0b0000_0000_0000_0000u16 }`.

## 🀄 Show me some code _dang it!_

##### > Building a basic unsigned `.vach` file

```
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig};

let config = BuilderConfig::default();
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
// builder.add(File::open("test_data/background.wav")?, "ambient").unwrap();
// builder.add(File::open("test_data/footstep.wav")?, "ftstep").unwrap();
builder.add(Cursor::new(b"Hello, Cassandra!"), "hello").unwrap();

// let mut target = File::create("sounds.vach")?;
let mut target = Cursor::new(Vec::new());

// The number of bytes written to the file
let size = builder.dump(&mut target, &config).unwrap();
```

##### > Loading resources from an unsigned `.vach` file

```ignore
use std::fs::File;
use vach::prelude::{Archive, Resource, Flags};

let target = File::open("sounds.vach")?;
let mut archive = Archive::from_handle(target)?;
let resource: Resource = archive.fetch("ambient")?;

// By default all resources are flagged as NOT secured
println!("{}", Sound::new(&resource.data)?);
assert!(!resource.secured);

let mut buffer = Vec::new();
let (flags, content_version, is_secure) = archive.fetch_write("ftstep", &mut buffer)?;
```

##### > Build a signed `.vach` file

```
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig, Keypair};
use vach::utils::gen_keypair;

let keypair: Keypair = gen_keypair();
let config: BuilderConfig = BuilderConfig::default().keypair(keypair);
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
// builder.add(File::open("test_data/background.wav")?, "ambient").unwrap();
// builder.add(File::open("test_data/footstep.wav")?, "ftstep").unwrap();
builder.add(Cursor::new(b"Hello, Cassandra!"), "hello").unwrap();

// let mut target = File::create("sounds.vach")?;
let mut target = Cursor::new(Vec::new());

builder.dump(&mut target, &config).unwrap();
```

##### > Serialize and de-serialize a `Keypair`, `SecretKey` and `PublicKey`

As `Keypair`, `SecretKey` and `PublicKey` are reflected from [ed25519_dalek](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/), you could refer to their docs to read further about them.

```
use vach::prelude::{Keypair, SecretKey, PublicKey};
use vach::utils::gen_keypair;

// Generate keys
let keypair : Keypair  = gen_keypair();
let secret : SecretKey = keypair.secret;
let public : PublicKey = keypair.public;

// Serialize
let public_key_bytes : [u8; vach::PUBLIC_KEY_LENGTH] = public.to_bytes();
let secret_key_bytes : [u8; vach::SECRET_KEY_LENGTH] = secret.to_bytes();
// let keypair_bytes : [u8; vach::KEYPAIR_LENGTH]    = keypair.to_bytes();

// Deserialize
let public_key : PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
let secret_key : SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
// let keypair : Keypair   = Keypair::from_bytes(&keypair_bytes).unwrap();
```

##### > Load resources from a signed `.vach` source

```ignore
// Load public_key
let mut public_key = File::open(PUBLIC_KEY)?;
let mut public_key_bytes: [u8; crate::PUBLIC_KEY_LENGTH];
public_key.read_exact(&mut public_key_bytes)?;

// Build the Loader config
let mut config = HeaderConfig::default().key(PublicKey::from_bytes(&public_key_bytes)?);

let target = File::open("sounds.vach")?;
let mut archive = Archive::with_config(target, &config)?;

// Resources are marked as secure (=true) if the signatures match the data
let resource = archive.fetch("ambient")?;
println!("{}", Sound::new(&resource.data)?);
assert!(resource.secured);
```
*/

/// All tests are included in this module.
mod tests;

pub(crate) mod global;
pub(crate) mod loader;
pub(crate) mod writer;

// Re-exports
pub use rand;

/// Current file spec version, both `Loader` and [`Builder`](crate::builder::Builder)
pub const VERSION: u16 = 30;

/// Size of a keypair: (secret + public)
pub const KEYPAIR_LENGTH: usize = 64;

/// Size of a secret key
pub const SECRET_KEY_LENGTH: usize = 32;

/// Size of a public key
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Size of a signature
pub const SIGNATURE_LENGTH: usize = 64;

/// Maximum size for any ID
pub const MAX_ID_LENGTH: usize = 65535; // u16::MAX

/// The default MAGIC used by `vach`
pub const DEFAULT_MAGIC: &[u8; 5] = b"VfACH";

/// The standard size of any MAGIC entry in bytes
pub const MAGIC_LENGTH: usize = 5;

/// Consolidated import for crate logic; This module stores all `structs` associated with this crate. Constants can be accesses [directly](#constants) with `crate::<CONSTANT>`
pub mod prelude {
	pub use crate::crypto::*;
	pub use crate::archive::*;
	pub use crate::builder::*;
}

/// Import keypairs and signatures from here, mirrors from `ed25519_dalek`
pub mod crypto {
	pub use ed25519_dalek::{Keypair, PublicKey, SecretKey};
}

/// [`Builder`] related data structures and logic
pub mod builder {
	pub use crate::writer::{
		builder::{Builder, BuilderConfig},
		leaf::{Leaf, CompressMode},
	};
	pub use crate::global::{
		error::InternalError, compressor::CompressionAlgorithm, result::InternalResult,
		flags::Flags,
	};
}

/// Loader-based logic and data-structures
pub mod archive {
	pub use crate::loader::{archive::Archive, resource::Resource};
	pub use crate::global::{
		reg_entry::RegistryEntry, header::HeaderConfig, error::InternalError,
		result::InternalResult, compressor::CompressionAlgorithm, flags::Flags,
	};
}

/// Some utility functions to keep you happy
pub mod utils;
