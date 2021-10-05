### 👔 The official `vach` and `vf` crates' repo

`vach`, pronounced like "fuck" but with a "v", is a archiving and resource transmission format. It was built to be secure, contained and protected ( _once encryption is implemented_ ). It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. `vach` also has in-built support for [compression](https://github.com/PSeitz/lz4_flex), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/0.1.5/vach/prelude/struct.Flags.html#) and archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/virtfs-rs/blob/main/spec/main.txt)**. Any and *all* help will be much appreciated, especially proof reading the docs and code review.

---

### 👄 Terminologies

- **Archive:** Any source of data, for example a file or TCP stream, that is a valid `vach` data source.
- **Leaf:** Any actual data endpoint within an archive, for example `footstep1.wav` in `sounds.vach`.
- **Entry:** Some data in the registry section of a `vach` source on an corresponding `leaf`. For example, `{ id: footstep.wav, location: 45, offset: 2345, flags: 0b0000_0000_0000_0000u16 }`.

---

### 🀄 Show me some code _dang it!_

##### > Building a basic `.vach` file

```rust

let mut builder = Builder::default();
let build_config = BuilderConfig::default();

builder.add(File::open("test_data/background.wav")?, "ambient")?;
builder.add(File::open("test_data/footstep_1.wav")?, "ftstep_1")?;
builder.add(Cursor::new(b"Hello, Cassandra!"), "hello")?;

let mut target = File::create(SIMPLE_TARGET)?;
builder.dump(&mut target, &build_config)?;

Ok(())
```

---

### 🛠 Yet to be implemented

- [ ] An official **CLI**.
- [ ] Data encryption.
- [ ] Skynet.
