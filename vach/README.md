<p align="center">
  <img src="https://raw.githubusercontent.com/zeskeertwee/virtfs-rs/main/media/logo.png" alt=".vach logo" width="180" height="180">
</p>
<h1 align=center>
  <strong>vach</strong>
</h1>
<p align=center> A simple archiving format, designed for storing assets in compact secure containers </p>

<p align=center>
  <a href="https://docs.rs/vach"><img alt="docs.rs" src="https://img.shields.io/docsrs/vach?style=flat-square"></a>
  <a href="https://crates.io/crates/vach"><img alt="Crate Version on Crates.io" src="https://img.shields.io/crates/v/vach?style=flat-square"></a>
  <br/>
  <a href="https://github.com/zeskeertwee/virtfs-rs/blob/main/LICENSE"><img alt="GitHub" src="https://img.shields.io/github/license/zeskeertwee/vach?style=flat-square"></a>
  <a href="https://github.com/zeskeertwee/virtfs-rs/actions/workflows/rust.yml"><img alt="GitHub Build and Test actions" src="https://github.com/zeskeertwee/virtfs-rs/workflows/Rust/badge.svg"></a>
  <a href="https://github.com/zeskeertwee/virtfs-rs/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/zeskeertwee/virtfs-rs?style=flat-square"></a>
</p>
<p align=center>
 <a href="https://docs.rs/vach">Docs</a> | <a href="https://github.com/zeskeertwee/virtfs-rs">Repo</a>
</p>

---

`vach`, pronounced like "puck" but with a "v", is a archiving and resource transmission format. It was built to be secure, contained and protected. It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. `vach` also has in-built support for multiple compression schemes (LZ4, Snappy and Brolti), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/0.1.5/vach/prelude/struct.Flags.html#), [encryption](https://crates.io/crates/aes-gcm-siv/0.10.3) and some degree of archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/virtfs-rs/blob/main/spec/main.txt)**. Any and **all** help will be much appreciated, especially proof reading the docs and code review.

## Simple usage

```rust
use std::fs::File;
use vach::prelude::{Archive, Resource, Flags};

let target = File::open("sounds.vach")?;
let mut archive = Archive::from_handle(target)?;
let resource: Resource = archive.fetch("footstep.wav")?;

// By default all resources are flagged as NOT secure
assert!(!resource.secured);

// Use the data
use my_crate::Sound;
println!("{}", Sound::new(resource.data.as_slice())?);

// Read data directly into an `io::Write` stream
let mut buffer = Vec::new();
let (flags, content_version, is_secure) = archive.fetch_write("ftstep", &mut buffer)?;
```

> For more information on how to use the crate, read the [documentation](https://docs.rs/vach).
