<p align="center">
  <img src="media/logo.png" alt=".vach logo" width="180" height="180">
</p>
<h1 align=center>
  <strong>vach</strong>
</h1>
<p align=center> A simple archiving format, designed for storing assets in compact secure containers </p>

<p align=center>
  <a href="https://crates.io/crates/vach"><img alt="Crate Version on Crates.io" src="https://img.shields.io/crates/v/vach?style=flat-square"></a>
  <a href="https://docs.rs/vach"><img alt="docs.rs" src="https://img.shields.io/docsrs/vach?style=flat-square"></a>
  <br/>
  <a href="https://github.com/zeskeertwee/vach/blob/main/LICENSE"><img alt="GitHub" src="https://img.shields.io/github/license/zeskeertwee/vach?style=flat-square"></a>
  <a href="https://github.com/zeskeertwee/vach/actions/workflows/tests.yml"><img alt="GitHub Build and Test actions" src="https://github.com/zeskeertwee/vach/actions/workflows/tests.yml/badge.svg"></a>
  <a href="https://github.com/zeskeertwee/vach/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/zeskeertwee/vach?style=flat-square"></a>
</p>
<p align=center>
 <a href="https://docs.rs/vach">Docs</a> | <a href="https://github.com/zeskeertwee/vach">Repo</a>
</p>

## 👔 The official `vach` crates' repo

`vach`, pronounced like "puck" but with a "v", is an archiving and resource transmission format. It was built to be secure, contained and protected. It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. `vach` also has in-built support for multiple compression schemes (LZ4, Snappy and Brolti), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/latest/vach/archive/struct.Flags.html), [encryption](https://docs.rs/aes-gcm/latest/aes_gcm/) and some degree of archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/vach/blob/main/spec/main.txt)**. Any and *all* help will be much appreciated, especially proof reading the docs and code review.

---

### ⛏ Who is this for?

- You just released some software and don't want your assets pirated or easily read.
- You want a simple convinient way to manage, decompress, decrypt and authenticate assets in distribution.
- You want a pure Rust™️ archive format with no C bindings underneath (bindings **for** C may become available in the future).
- You want your product to be neat, and all your assets to be in one neat  secure container.

---

### 🤷 Who is what, when where?

- **vach:** An archiving format, like `tar`, `zip` and `rar`.  Also the base crate for handling `.vach` files in your application.
- **vach-cli:** <a href="https://crates.io/crates/vach-cli"><img alt="Crate Version on Crates.io" src="https://img.shields.io/crates/v/vach-cli?style=flat-square"></a> A CLI tool for dealing with `.vach` files.

---

### 👄 Terminologies

- **Archive Source:** Any source of data. That implements `io::Seek` and `io::Read`, for example a file (`fs::File`) or in memory buffer (`io::Cursor<Vec<u8>>`).
- **Leaf:** Any actual data endpoint within an archive, for example `footstep1.wav` in `sounds.vach`.
- **Entry:** Some data in the registry section of a `vach` source on an corresponding `leaf`. For example, `{ id: footstep.wav, location: 45, offset: 2345, flags: 0b0000_0000_0000_0000u16 }`.

---

### 🀄 Show me some code _dang it!_

##### > Building a basic unsigned `.vach` file

```rust
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig};

let config = BuilderConfig::default();
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
builder.add(File::open("test_data/background.wav")?, "ambient").unwrap();
builder.add(vec![12, 23, 34, 45, 56, 67, 78, 89, 10], "ftstep").unwrap();
builder.add(b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8], "hello").unwrap();

// let mut target = File::create("sounds.vach")?;
let mut target = Cursor::new(Vec::new());

// The number of bytes written to the file
let size = builder.dump(&mut target, &config).unwrap();
```

##### > Loading resources from an unsigned `.vach` file

```rust
use std::fs::File;
use vach::prelude::{Archive, Resource, Flags};

let target = File::open("sounds.vach")?;
let mut archive = Archive::new(target)?;
let resource: Resource = archive.fetch_mut("ambient")?;

// By default all resources are flagged as NOT authenticated
println!("{}", Sound::new(&resource.data)?);
assert!(!resource.authenticated);
```

##### > Build a signed `.vach` file

```rust
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig, Keypair};
use vach::crypto_utils::gen_keypair;

let keypair:      Keypair = gen_keypair();
let config:       BuilderConfig = BuilderConfig::default().keypair(keypair);
let mut builder:  Builder = Builder::default();

// Use different data types under the same builder umbrella, uses dynamic dispatch
let data_1 = vec![12, 23, 45, 56, 67 ,78, 89, 69];
let data_2 = File::open("test_data/footstep.wav").unwrap();
let data_3 = b"Hello, Cassandra!" as &[u8];

// Use `Builder::add( reader, ID )` to add data to the write queue
builder.add(data_3, "ambient").unwrap();
builder.add(data_2, "ftstep").unwrap();
builder.add(data_1.as_slice(), "hello").unwrap();

let mut target = File::create("sounds.vach")?;
builder.dump(&mut target, &config).unwrap();
```

##### > Serialize and de-serialize a `Keypair`, `SecretKey` and `PublicKey`

As `Keypair`, `SecretKey` and `PublicKey` are reflected from [ed25519_dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/), you could refer to their docs to read further about them.

```rust
use vach::prelude::{Keypair, SecretKey, PublicKey};
use vach::crypto_utils::gen_keypair;

// Generate keys
let keypair :   Keypair  = gen_keypair();
let secret :    SecretKey = keypair.secret;
let public :    PublicKey = keypair.public;

// Serialize
let public_key_bytes : [u8; vach::PUBLIC_KEY_LENGTH] = public.to_bytes();
let secret_key_bytes : [u8; vach::SECRET_KEY_LENGTH] = secret.to_bytes();
let keypair_bytes : [u8; vach::KEYPAIR_LENGTH]    = keypair.to_bytes();

// Deserialize
let public_key :  PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
let secret_key :  SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
let keypair :     Keypair   = Keypair::from_bytes(&keypair_bytes).unwrap();
```

##### > Load resources from a signed `.vach` source

```rust
// Load public_key
let mut public_key_bytes: [u8; crate::PUBLIC_KEY_LENGTH] = include_bytes!(PUBLIC_KEY);

// Build the Loader config
let mut config = ArchiveConfig::default().key(PublicKey::from_bytes(&public_key_bytes)?);

let target = File::open("sounds.vach")?;
let mut archive = Archive::with_config(target, &config)?;

// Resources are marked as secure (=true) if the signatures match the data
let resource = archive.fetch_mut("ambient")?;
println!("{}", Sound::new(&resource.data)?);
assert!(resource.authenticated);
```

##### > A quick consolidated example

```rust
const MAGIC: &[u8; 5] = b"CSDTD";
let mut target: Cursor<Vec<u8>> = Cursor::new(Vec::new());

// Data to be written
let data_1 = b"Around The World, Fatter better stronker" as &[u8];
let data_2 = b"Imagine if this made sense" as &[u8];
let data_3 = b"Fast-Acting Long-Lasting, *Bathroom Reader*" as &[u8];

// Builder definition
let mut builder = Builder::new();
let config = BuilderConfig::default().magic(*MAGIC);

// Add data
builder.add_leaf(Leaf::new(data_1).id("d1").compress(CompressMode::Always))?;
builder.add_leaf(Leaf::new(data_2).id("d2").compress(CompressMode::Never))?;
builder.add_leaf(Leaf::new(data_3).id("d3").compress(CompressMode::Detect))?;

// Dump data
builder.dump(&mut target, &config)?;

// Load data
let config = ArchiveConfig::default().magic(*MAGIC);
let mut archive = Archive::with_config(target, &config)?;

// Quick assertions
assert_eq!(archive.fetch_mut("d1")?.data.as_slice(), data_1);
assert_eq!(archive.fetch_mut("d2")?.data.as_slice(), data_2);
assert_eq!(archive.fetch_mut("d3")?.data.as_slice(), data_3);
```

> For more information on how to use the library, read the documentation. [Always read the documentation!](https://youtu.be/TUE_HSgQiG0?t=91) or read the tests, they offer great insight into how the crate works.

---

### 🛠 Yet to be implemented

- [x] An official **CLI**, [check it out](https://crates.io/crates/vach-cli).
- [x] Data encryption.
- [x] Benchmarks.
- [x] Features to turn off (or to turn on) either the `Builder` or the `Loader` modules.
- [x] `Some(examples)` instead of `None`
- [ ] Skynet, (coming _very_ soon).
- [ ] Some proper benchmarking code. (Call for participation)

> If you appreciate the works of this repo, consider dropping a star. It will be much appreciated; 🌟
