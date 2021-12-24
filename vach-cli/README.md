# **`vach-cli`**

`vach-cli` is a simple CLI for packing, unpacking and handling `.vach` files.

---

## **Installation**

```sh
cargo install vach-cli
```

## **Usage:**

Generally follows the template:

```sh
vach [subcommand] -[key] [...values]
```

```sh
# List all entries in the archive "source.vach"
vach list -i source.vach

# Pack the files hello.png, click.wav and dialogue.txt into asssets.vach
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

## **Commands:**

- Running `vach help` will list all the commands. They each have their own inputs.

- Also check out `spec/main.txt` for the official spec.

- You can also run `vach [command] --help` to see help on each individual command.

- Because of how the CLI works, the positions of the keys does not matter, so:

   `vach list -i target.vach -m CMYKV` and `vach list -m CMYKV -i target.vach` are equivalent.

---

### 1: pack

> `pack` is used to pack files and directories into archives. It takes inputs for customizing how the archive should be packaged.

```sh
# The simplest pack command.
# Any pack command must have an output, set using the "-o" or "--output" keys
# This builds only an empty archive
vach pack -o hello.vach

# You can add files as inputs using the "-i" or --input" keys
vach pack -o hello.vach -i hello.txt goodbye.txt

# Or add a directory using "-d" or "--directory"
vach pack -o hello.vach -d ./hello

# Add a directory recursively using "-r" or "--directory-r"
vach pack -o hello.vach -r ./hello

# Inputs can be added in tandem
vach pack -o hello.vach -i hi.txt bye.txt -d greetings PR -r talks

# Also use another archive as input using the "-z" or "--source" flag
# The other archive should be standard, meaning no encryption nor custom magic. Tho it can be compressed
vach pack -z another.vach -o hello.vach -i hello.txt goodbye.txt

# Exclude a given file from the queue
vach pack -x hello/secret.txt -o hello.vach -d hello

# Provide a keypair or secret key for cryptographic use
vach pack -k keypair.kp -o hello.vach -i hello.txt goodbye.txt
vach pack -s secret_key.sk -o hello.vach -i hello.txt goodbye.txt

### MODIFIERS ####
# Compression: "-c always", "-c never" or "-c detect"
vach pack -c always -o hello.vach -i hello.txt goodbye.txt

# Hash: "-h" or "--hash"
# Whether to include signatures in the archive
# This help to detect if the archive has been tampered with
# But there are very computationaly intensive so use them sparingly
vach pack -s -o hello.vach -i hello.txt goodbye.txt

# Encrypt: "-e" or "--encrypt"
# Whether to encrypt your archive
# If no pre-existing keypair|secret_key is provided then a new one is written: `${OUTPUT_ARCHIVE}.kp`
# EG hello.vach -> hello.vach.kp, same applies for "-h"
vach pack -e -o hello.vach -i hello.txt goodbye.txt

# Flags: "-f" or "--flags"
# Flags for the archive globally
# Here the flags are set to 0b1000_1100_1001_0000
vach pack -f 35984 -o hello.vach -i hello.txt goodbye.txt

# Magic: "-m" or "--magic"
# Make your archive unique by setting a custom MAGIC
vach pack -m CMYKX -o hello.vach -i hello.txt goodbye.txt

# Truncate: "-t" or "--truncate"
# This modifier deletes the original files once they are packaged
# hello.txt & goodbye.txt are now deleted
vach pack -t -o hello.vach -i hello.txt goodbye.txt
```

### 2: unpack

>`unpack` is used to unpack archives back into their constituent files.

```sh
# The simplest unpack command
# Provide an input: "-i" or "--input"
vach unpack -i target.vach

# Output directory: "-o" or "--output"
# Specify where to unpack the archive
vach unpack -i source.vach -o ./output/

# Specify what magic your archive uses
# Magic: "-m" or "--magic"
vach unpack -m CMYKX -i source.vach

# Truncate: "-t" or "--truncate"
# Deletes the original archive after unpacking
vach unpack -t -i source.vach

# If the archive is encrypted then provide a keypair or public key
vach unpack -k keypair.kp -i source.vach
vach unpack -s keypair.sk -i source.vach
```

### 3: list

> Lists all the entries in the archive as a table

```sh
# The simplest list command
# Provide some input: "-i" or "--input"
vach list -i textures.vach

# MAGIC: "-m" or "--magic"
# If the archive uses a custom magic
vach list -i textures.vach -m TXTRS
```

### 4: verify

> Verifies the validity of a file as an archive

```sh
# Simplest command
vach verify -i textures.vach

# MAGIC: "-m" or "--magic"
vach verify -i textures.vach -m TXTRS
```

### 5: keypair

> Key-pair generation command

```sh
vach keypair -o keypair.kp
# -> keypair.kp

# Splits the keypair into it's secret and public components immediately after generation
vach keypair -s -o keypair.kp

# -> keypair.pk
# -> keypair.sk
```

### 6: split

> Splits an existing keypair into it's public and secret components

```sh
vach split -i keypair.kp

# -> keypair.pk
# -> keypair.sk
```
