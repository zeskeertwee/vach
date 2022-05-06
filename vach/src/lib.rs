#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::or_fun_call)]
#![allow(clippy::manual_map)]
#![deny(missing_docs)]

/*!
#### A simple archiving format, designed for storing assets in compact secure containers

`vach`, pronounced like "puck" but with a "v", is an archiving and resource transmission format. It was built to be secure, contained and protected. It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. `vach` also has in-built support for multiple compression schemes (LZ4, Snappy and Brolti), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/latest/vach/archive/struct.Flags.html), [encryption](https://docs.rs/aes-gcm/latest/aes_gcm/) and some degree of archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/virtfs-rs/blob/main/spec/main.txt)**. Any and *all* help will be much appreciated, especially proof reading the docs and code review.

### 👄 Terminologies

- **Archive:** Any source of data, for example a file or TCP stream, that is a valid `vach` data source.
- **Leaf:** Any actual data endpoint within an archive, what `tar` calls archive members, for example `footstep1.wav` in `sounds.vach`.
- **Entry:** Some data in the registry section of a `vach` source on an corresponding [leaf](crate::builder::Leaf). For example, `{ id: footstep.wav, location: 45, offset: 2345, flags: 0b0000_0000_0000_0000u16 }`.

### 🔫 Cargo Features
- `loader` and `builder` (default): Turning them off turns off their respective modules. For example a game only needs the `loader` feature but a tool for packing assets would only need the `builder` feature.
- `multithreaded`: Pulls [rayon](https://crates.io/crates/rayon) as a dependency and adds `Send + Sync` as a trait bound to many generic types.
  This allows for the auto-parallelization of the `Builder::dump(---)` function and adds a new `Archive::fetch_batch(---)` method, with more functions getting parallelization on the way.

  > Turning this feature on adds a several new dependencies that would be completely unnecessary for a smaller scope, its only benefits when several entries are required at one moment there can be fetched simultaneously_

- `compression`: Pulls `snap`, `lz4_flex` and `brotli` as dependencies and allows for compression in `vach` archives.
- `crypto`: Enables encryption and authentication functionality by pulling the `ed25519_dalek` and `aes_gcm` crates

### 🀄 Show me some code _dang it!_

##### > Building a basic unsigned `.vach` file

```ignore
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig};

let config = BuilderConfig::default();
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
// Adds any data that implements `io::Read`
builder.add(File::open("test_data/background.wav")?, "ambient").unwrap();
builder.add(&[12, 23, 34, 45, 56, 67, 78, 90, 69], "ftstep").unwrap();
builder.add(b"Hello, Cassandra!", "hello").unwrap();

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
let archive = Archive::from_handle(target)?;
let resource: Resource = archive.fetch("ambient")?;

// By default all resources are flagged as NOT secured
println!("{}", Sound::new(&resource.data)?);
assert!(!resource.secured);

let mut buffer = Vec::new();
let (flags, content_version, is_secure) = archive.fetch_write("ftstep", &mut buffer)?;
```

##### > Build a signed `.vach` file

```ignore
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig, Keypair};
use vach::utils::gen_keypair;

let keypair: Keypair = gen_keypair();
let config: BuilderConfig = BuilderConfig::default().keypair(keypair);
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
builder.add(File::open("test_data/background.wav")?, "ambient").unwrap();
builder.add(vec![12, 23, 34, 45, 56, 67, 78], "ftstep").unwrap();
builder.add(b"Hello, Cassandra!" as &[u8], "hello").unwrap();

let mut target = File::create("sounds.vach")?;
builder.dump(&mut target, &config).unwrap();

let mut target = Cursor::new(Vec::new());
builder.dump(&mut target, &config).unwrap();
```

##### > Serialize and de-serialize a `Keypair`, `SecretKey` and `PublicKey`

As `Keypair`, `SecretKey` and `PublicKey` are reflected from [ed25519_dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/), you could refer to their docs to read further about them.

```ignore
use vach::prelude::{Keypair, SecretKey, PublicKey};
use vach::utils::gen_keypair;

// Generate keys
let keypair : Keypair  = gen_keypair();
let secret : SecretKey = keypair.secret;
let public : PublicKey = keypair.public;

// Serialize
let public_key_bytes : [u8; vach::PUBLIC_KEY_LENGTH] = public.to_bytes();
let secret_key_bytes : [u8; vach::SECRET_KEY_LENGTH] = secret.to_bytes();
let keypair_bytes : [u8; vach::KEYPAIR_LENGTH]    = keypair.to_bytes();

// Deserialize
let public_key : PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
let secret_key : SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
let keypair : Keypair   = Keypair::from_bytes(&keypair_bytes).unwrap();
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
let archive = Archive::with_config(target, &config)?;

// Resources are marked as secure (=true) if the signatures match the data
let resource = archive.fetch("ambient")?;
println!("{}", Sound::new(&resource.data)?);
assert!(resource.secured);
```
*/

/// All tests are included in this module.
mod tests;

pub(crate) mod global;
#[cfg(feature = "loader")]
#[cfg_attr(docsrs, doc(cfg(feature = "loader")))]
pub(crate) mod loader;

#[cfg(feature = "builder")]
#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
pub(crate) mod writer;

// Re-export
#[cfg(feature = "crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
pub use rand;

#[cfg(feature = "multithreaded")]
#[cfg_attr(docsrs, doc(cfg(feature = "multithreaded")))]
pub use {rayon, num_cpus};

/// Current [`vach`](crate) spec version. increments by ten with every spec change
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
	pub use crate::global::{
		error::InternalError, result::InternalResult, flags::Flags, header::HeaderConfig, reg_entry::RegistryEntry,
	};

	#[cfg(feature = "crypto")]
	pub use crate::crypto::*;

	#[cfg(feature = "loader")]
	pub use crate::archive::*;

	#[cfg(feature = "builder")]
	pub use crate::builder::*;
}

/// Import keypairs and signatures from here, mirrors from `ed25519_dalek`
pub mod crypto;

/// [`Builder`](crate::builder::Builder) related data structures and logic
#[cfg(feature = "builder")]
#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
pub mod builder {
	pub use crate::writer::{
		builder::{Builder, BuilderConfig},
		leaf::Leaf,
	};
	pub use crate::global::{error::InternalError, result::InternalResult, flags::Flags};

	#[cfg(feature = "compression")]
	pub use crate::writer::compress_mode::CompressMode;
	#[cfg(feature = "compression")]
	pub use crate::global::compressor::CompressionAlgorithm;
}

/// Loader-based logic and data-structures
#[cfg(feature = "loader")]
#[cfg_attr(docsrs, doc(cfg(feature = "loader")))]
pub mod archive {
	pub use crate::loader::{archive::Archive, resource::Resource};
	pub use crate::global::{
		reg_entry::RegistryEntry, header::HeaderConfig, error::InternalError, result::InternalResult, flags::Flags,
	};
	#[cfg(feature = "compression")]
	pub use crate::global::compressor::CompressionAlgorithm;
}

/// Some utility functions to keep you happy
pub mod utils;
