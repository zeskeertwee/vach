use clap::{Parser, Subcommand, ValueEnum};
use std::{path::PathBuf, thread};

use crate::commands::{self, CommandTrait};

#[derive(Debug, Clone, ValueEnum)]
pub enum SortSetting {
	Alphabetical,
	AlphabeticalReversed,
	SizeAscending,
	SizeDescending,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CompressModeSetting {
	Always,
	Never,
	Auto,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum CompressionAlgorithmSetting {
	LZ4,
	Snappy,
	Brotli,
}

#[derive(Parser)]
#[command(name = "vach-cli")]
#[command(version, author, about, long_about = None)]
#[command(next_line_help = true)]
pub struct CommandLine {
	#[command(subcommand)]
	/// What class of operation do you fancy?
	pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
	/// Unpack an archive to the filesystem
	#[command(version = commands::unpack::Subcommand::version())]
	Unpack {
		/// Path to file to unpack
		#[arg(short, long, value_name = "FILE")]
		input: PathBuf,
		/// Directory to unpack to
		#[arg(short, long, value_name = "DIR")]
		output: Option<PathBuf>,
		/// Path to keypair to use for cryptographic operations
		#[arg(short, long, value_name = "FILE")]
		keypair: Option<PathBuf>,
		/// Path to public key to use for cryptographic operations
		#[arg(short, long, value_name = "FILE")]
		public_key: Option<PathBuf>,
		/// Number of threads to spawn during unpacking, prefer using one thread for small archives
		#[arg(short, long, default_value_t = thread::available_parallelism().unwrap().get(), value_name = "THREADS")]
		jobs: usize,
		/// How may entries to process per thread, [default: archive.entries.count / jobs]
		#[arg(short, long, value_name = "BATCH")]
		chunks_size: Option<usize>,
	},
	/// Unpacks a resource and writes to stdout
	#[command(version = commands::pipe::Subcommand::version())]
	Pipe {
		/// Path to file to unpack
		#[arg(short, long, value_name = "FILE")]
		input: PathBuf,
		/// The `id` of the resource to extract
		#[arg(short, long, value_name = "ID")]
		resource: String,
		/// Path to keypair to use for cryptographic operations
		#[arg(short, long, value_name = "FILE")]
		keypair: Option<PathBuf>,
		/// Path to public key to use for cryptographic operations
		#[arg(short, long, value_name = "FILE")]
		public_key: Option<PathBuf>,
	},
	/// List metadata and entries in an archive,
	#[command(version = commands::list::Subcommand::version())]
	List {
		/// Path to file to list
		#[arg(short, long, value_name = "FILE")]
		input: PathBuf,
		/// How to sort the listed entries
		#[arg(short, long, value_name = "SORT", value_enum)]
		sort: Option<SortSetting>,
	},
	/// Check an input file is a valid .vach archive
	#[command(version = commands::verify::Subcommand::version())]
	Verify {
		/// Path to file to verify
		#[arg(value_name = "FILE")]
		input: PathBuf,
	},
	/// Generate a keypair (verifying & signing key)
	#[command(name = "keypair")]
	#[command(version = commands::keypair::Subcommand::version())]
	GenKeypair {
		/// Path to output keypair files
		#[arg(short, long, default_value_t = String::from("keypair.kp"), value_name = "PATH")]
		output: String,
		/// Whether to output keypair as separate signing and verifying keys
		#[arg(short, long, default_value_t = true)]
		split_key: bool,
	},
	/// Pack some files into a .vach archive
	#[command(version = commands::pack::Subcommand::version())]
	Pack {
		/// Input files to include in the archive
		#[arg(short, long, value_name = "FILES", num_args=1..)]
		inputs: Option<Vec<PathBuf>>,
		/// New archive will be output to this path
		#[arg(short, long, value_name = "PATH")]
		output: PathBuf,
		/// Includes files from these directories, non-recursively
		#[arg(short, long, num_args=1..)]
		directories: Option<Vec<PathBuf>>,
		/// Includes files from these directories, recursively
		#[arg(short, long = "recursive", value_name = "DIRECTORIES", num_args=1..)]
		recursive_directories: Option<Vec<PathBuf>>,
		/// Input files to include in the archive
		#[arg(short = 'x', long, value_name = "PATHS", num_args=1..)]
		exclude: Option<Vec<PathBuf>>,
		/// Compression Mode for entries, `Auto` picks the better on a per-entry basis
		#[arg(short, long = "c-mode", value_name = "MODE", value_enum)]
		compress_mode: Option<CompressModeSetting>,
		/// Compression algorithm to use for entries
		#[arg(short = 'a', long = "c-algo", value_name = "ALGO", value_enum)]
		compression_algorithm: Option<CompressionAlgorithmSetting>,
		/// Path to keypair to use for cryptographic operations
		#[arg(short, long, value_name = "FILE")]
		keypair: Option<PathBuf>,
		/// Path to private key to use for cryptographic operations
		#[arg(short = 'p', long, value_name = "FILE")]
		private_key: Option<PathBuf>,
		/// Encrypts the data using the provided keypair, using AesGcm256
		#[arg(short, long)]
		encrypt: bool,
		/// Whether to sign entries and include signatures in the header
		#[arg(short, long)]
		sign: bool,
		/// Flags to include in header section of archive
		#[arg(short, long)]
		flags: Option<u32>,
		/// Number of threads to spawn during packing
		#[arg(short, long, default_value_t = thread::available_parallelism().unwrap().get(), value_name = "THREADS")]
		jobs: usize,
	},
}
