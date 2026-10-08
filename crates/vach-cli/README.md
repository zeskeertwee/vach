# **`vach-cli`**

`vach-cli` is a simple CLI for packing, unpacking and handling `.vach` files.

> For the [`vach20`](https://crates.io/crates/vach/0.2.3) version use [this version](https://crates.io/crates/vach-cli/0.3.3) of the CLI instead, this version of the CLI only works with [`vach30`](https://crates.io/crates/vach/0.3.5) onwards

---

## **Installation**

```sh
cargo install vach-cli
```

## **Usage:**

Generally follows the template:

```sh
vach [subcommand] --switch value -s value
```

```sh
# List all entries in the archive "source.vach"
vach list -i source.vach

# Pack the files hello.png, click.wav and dialogue.txt into assets.vach
vach pack -i hello.png click.wav dialogue.tx -o assets.vach

# Pack all the file in the directory textures into textures.vach and apply compression
vach pack -d textures -o textures.vach -c

# This lists out the contents of textures.vach
vach list -i textures.vach
┌───────────────────────────┬───────┬────────────┐
│          id               │ size  │   flags    │
├───────────────────────────┼───────┼────────────┤
│   textures/perlin.png     │ 698 B │ Flags[C--] │
│    textures/dirt.png      │ 391 B │ Flags[C--] │
│   textures/cobble.png     │ 733 B │ Flags[C--] │
│    textures/map.json      │ 311 B │ Flags[C--] │
└───────────────────────────┴───────┴────────────┘
```

---

## **Subcommand Documentation:**

Run `vach help` to list available commands:

```
$ vach  --help

A command-line tool to work with vach archive files and streams

Usage: ./vach <COMMAND>

Commands:
  unpack
          Unpack an archive to the filesystem
  pipe
          Unpacks a resource and writes to stdout
  list
          List metadata and entries in an archive,
  verify
          Check an input file is a valid .vach archive
  keypair
          Generate a keypair (verifying & signing key)
  pack
          Pack some files into a .vach archive
  help
          Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help
  -V, --version
          Print version
```

Further run `vach [cmd] --help` to display help information per `[cmd]` command. For example for `vach pipe`:

```sh
$ vach pipe  --help

Unpacks a resource and writes to stdout

Usage: ./vach pipe [OPTIONS] --input <FILE> --resource <ID>

Options:
  -i, --input <FILE>
          Path to archive to unpack
  -r, --resource <ID>
          The `id` of the resource to extract
  -k, --keypair <FILE>
          Path to keypair to use for cryptographic operations
  -p, --public-key <FILE>
          Path to public key to use for cryptographic operations
  -h, --help
          Print help
  -V, --version
          Print version
```
