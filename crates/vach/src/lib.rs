#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::or_fun_call)]
#![allow(clippy::manual_map)]
#![deny(missing_docs)]

/*!
![GitHub last commit](https://img.shields.io/github/last-commit/zeskeertwee/vach?logo=rust&logoColor=orange&style=flat-square)
#### A simple archiving format, designed for storing assets in compact secure containers

`vach` is an archiving and resource transmission format.
It was built to be secure, contained and protected. A big benefit of `vach` is the fine grained control it grants it's users, as it allows for per-entry independent configuration.
`vach` also has in-built support for multiple compression schemes (LZ4, Snappy and Brolti), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/latest/vach/archive/struct.Flags.html), [encryption](https://docs.rs/aes-gcm/latest/aes_gcm/) and some degree of archive customization.

> Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/vach/blob/main/spec/main.txt)**.

### 👄 Terminologies

- **Archive:** Any source of data, for example a file or TCP stream, that is a valid `vach` data source.
- **Leaf:** Any actual data endpoint within an archive, what `tar` calls archive members, for example `footstep1.wav` in `sounds.vach`.
- **Entry:** Some data in the registry section of a `vach` source on an corresponding [leaf](crate::builder::Leaf). For example, `{ id: footstep.wav, location: 45, offset: 2345, flags: 0b0000_0000_0000_0000u16 }`.

### 🔫 Cargo Features
- `archive` and `builder` (default): Turning them off turns off their respective modules. For example a game only needs the `archive` feature but a tool for packing assets would only need the `builder` feature.
- `multithreaded`: Runs `Builder::dump(---)` on multiple threads. Number of threads can be set manually using `BuilderConfig::num_threads`
- `compression`: Pulls `snap`, `lz4_flex` and `brotli` as dependencies and allows for compression in `vach` archives.
- `crypto`: Enables encryption and authentication functionality by pulling the `ed25519_dalek` and `aes_gcm` crates
- `default`: Enables the `archive` and `builder` features.
- `all`: Enables all the features listed above

### 🀄 Show me some code _dang it!_

```
use std::{io::Cursor, fs::File};
use vach::prelude::*;

// collect leaves in a vector, or static buffer
let mut leaves = [
	// Leaf::new(File::open("test_data/background.wav").unwrap(), "ambient"),
	Leaf::new([12, 23, 34, 45, 56, 67, 78, 90, 69].as_slice(), "ftstep"),
	Leaf::new(b"Hello, Cassandra!".as_slice(), "hello")
];

// let mut target = File::create("sounds.vach")?;
let mut target = Cursor::new(Vec::new());

let config = BuilderConfig::default();
let bytes_written = dump(&mut target, &mut leaves, &config, None).unwrap();

// roundtrip
let mut archive = Archive::new(target).unwrap();
let resource = archive.fetch_mut("ftstep").unwrap();

assert_eq!(resource.data.as_ref(), [12, 23, 34, 45, 56, 67, 78, 90, 69].as_slice());
```
*/

/// All tests are included in this module.
mod tests;

pub(crate) mod global;

#[cfg(feature = "archive")]
#[cfg_attr(docsrs, doc(cfg(feature = "archive")))]
pub(crate) mod loader;

#[cfg(feature = "builder")]
#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
pub(crate) mod writer;

/// Current [`vach`](crate) spec version. increments by ten with every spec change
pub const VERSION: u16 = 30;

/// Size of a secret key
pub const SECRET_KEY_LENGTH: usize = 32;

/// Size of a public key
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Size of a signature
pub const SIGNATURE_LENGTH: usize = 64;

/// Maximum size for any ID, ie u16::MAX
pub const MAX_ID_LENGTH: usize = u16::MAX as usize;

/// The standard size of any MAGIC entry in bytes
pub const MAGIC_LENGTH: usize = 5;

/// The default MAGIC used by `vach`
pub const DEFAULT_MAGIC: [u8; crate::MAGIC_LENGTH] = *b"VfACH";

/// Consolidated import for crate logic; This module stores all `structs` associated with this crate. Constants can be accesses [directly](#constants) with `crate::<CONSTANT>`
pub mod prelude {
	pub use crate::global::{error::*, flags::Flags, header::ArchiveConfig, reg_entry::RegistryEntry};

	#[cfg(feature = "crypto")]
	pub use crate::crypto::*;

	#[cfg(feature = "archive")]
	pub use crate::archive::*;

	#[cfg(feature = "builder")]
	pub use crate::builder::*;

	#[cfg(feature = "compression")]
	pub use crate::global::compressor::*;
}

/// Import keypairs and signatures from here, mirrors from `ed25519_dalek`
pub mod crypto;

/// Archive Creation logic and data structures, [`dump`](crate::builder::dump), [`Leaf`](crate::builder::Leaf) and [`BuilderConfig`](crate::builder::BuilderConfig)
#[cfg(feature = "builder")]
#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
pub mod builder {
	pub use crate::writer::*;
	pub use crate::global::{error::*, flags::Flags};

	#[cfg(feature = "compression")]
	pub use crate::global::compressor::CompressionAlgorithm;
}

/// Loader-based logic and data-structures
#[cfg(feature = "archive")]
#[cfg_attr(docsrs, doc(cfg(feature = "archive")))]
pub mod archive {
	pub use crate::loader::{archive::Archive, resource::Resource};
	pub use crate::global::{reg_entry::RegistryEntry, header::ArchiveConfig, error::*, flags::Flags};
	#[cfg(feature = "compression")]
	pub use crate::global::compressor::CompressionAlgorithm;
}

/// Some utility functions to keep you happy
pub mod crypto_utils;
