<p align=center>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/zeskeertwee/vach?logo=rust&logoColor=orange&style=flat-square">
  <a href="https://docs.rs/vach"><img alt="docs.rs" src="https://img.shields.io/docsrs/vach?style=flat-square"></a>
  <a href="https://crates.io/crates/vach"><img alt="Crate Version on Crates.io" src="https://img.shields.io/crates/v/vach?style=flat-square"></a>
  <br/>
  <a href="https://github.com/zeskeertwee/vach/blob/main/LICENSE"><img alt="GitHub" src="https://img.shields.io/github/license/zeskeertwee/vach?style=flat-square"></a>
  <a href="https://github.com/zeskeertwee/vach/actions/workflows/tests.yml"><img alt="GitHub Build and Test actions" src="https://github.com/zeskeertwee/vach/actions/workflows/tests.yml/badge.svg"></a>
  <a href="https://github.com/zeskeertwee/vach/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/zeskeertwee/vach?style=flat-square"></a>
</p>
<p align=center>
 <a href="https://docs.rs/vach">Docs</a> | <a href="https://github.com/zeskeertwee/vach">Repo</a>
</p>

`vach`, pronounced like "puck" but with a "v", is an archiving and resource transmission format. It was built to be secure, contained and protected. It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. A big benefit of `vach` is the fine grained control it grants it's users, as it allows for per-entry independent configuration. `vach` also has in-built support for multiple compression schemes (LZ4, Snappy and Brolti), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/latest/vach/archive/struct.Flags.html), [encryption](https://docs.rs/aes-gcm/latest/aes_gcm/) and some degree of archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/vach/blob/main/spec/main.txt)**. Any and *all* help will be much appreciated, especially proof reading the docs and code review.

## ⛏ Who is this for?

- You just released some software and don't want your assets pirated or easily read.
- You want a simple convenient way to manage, decompress, decrypt and authenticate assets in distribution.
- You want a pure Rust™️ archive format with no C bindings underneath (bindings **for** C may become available in the future).
- You want your software to be neat, and all your assets to be in one neat secure container.
- You like orbital cannons.

## 🧷 Simple usage

```rust
use std::fs::File;
use vach::prelude::{Archive, Resource, Flags};

let source = File::open("sounds.vach")?;

let mut archive = Archive::new(source)?;
let resource: Resource = archive.fetch_mut("footstep.wav")?;

// By default all resources are flagged as NOT secure
assert!(!resource.authenticated);

// Use the data
use my_crate::Sound;
println!("{}", Sound::new(resource.data.as_slice())?);

// Read data directly into an `io::Write` stream
let mut buffer = Vec::new();
let (flags, content_version, is_secure) = archive.fetch_mut("ftstep", &mut buffer)?;
```

> For more information on how to use the crate, read the [documentation](https://docs.rs/vach) or pass by the [repository](https://github.com/zeskeertwee/vach). Maybe also check out the [CLI](https://crates.io/crates/vach-cli), for a more user-friendly use of `vach`
