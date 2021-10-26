use std::{env, fs};
use vach::prelude::*;

fn main() {
	let mut args = env::args().collect::<Vec<String>>();

	// Fetch data
	let command = args.get(1).unwrap().as_str();
	let input = args.get(2).unwrap();

	match command {
		"-l" | "--list" => {
			let file = fs::File::open(input).unwrap();
			let archive = Archive::from_handle(file).unwrap();
			let pad = |mut ex: String, len: usize| -> String {
				if ex.len() >= len {
					ex.truncate(len - 4);
					ex.push_str("... ");
					ex
				} else {
					while ex.len() <= len {
						 ex.push(' ');
					}
					ex
				}
			};

			println!(
				"|{}ID{}SIZE------------FLAGS.{}|",
				"-".repeat(1),
				"-".repeat(34),
				"-".repeat(60)
			);
			for (id, entry) in archive.entries() {
				let id_copy = id.clone();
				let flags = entry.flags.to_string();
				let offset = entry.offset.to_string();

				println!(
					"| {} | {} | {} |",
					pad(id_copy, 32),
					pad(offset, 12),
					pad(flags, 64)
				);
			}
			println!("|{}|", "-".repeat(119));
		}
		"-f" | "--fetch" => {
			if let Some(id) = args.get(3) {
				let file = fs::File::open(input).unwrap();
				let mut archive = Archive::from_handle(file).unwrap();

				archive.fetch_write(id.as_str(), std::io::stdout()).unwrap();
			} else {
				panic!("Please provide a ID to fetch")
			}
		}
		"-d" | "--dump" => {
			if let Some(id) = args.get(3) {
				let file = fs::File::open(input).unwrap();
				let mut archive = Archive::from_handle(file).unwrap();

				let path = match args.get(4) {
					Some(of) => of,
					None => panic!("Provide a filename to write to"),
				};

				let file = fs::OpenOptions::new()
					.write(true)
					.create(true)
					.open(path)
					.unwrap();

				archive.fetch_write(id.as_str(), file).unwrap();
			} else {
				panic!("Please provide a ID to fetch")
			}
		}
		"-b" | "--build" => {
			let target_path = match args.get(2) {
				Some(of) => of,
				None => panic!("Provide a filename to write to"),
			};

			let target = fs::OpenOptions::new()
				.write(true)
				.create(true)
				.open(target_path)
				.unwrap();

			let template = Leaf::default().compress(CompressMode::Detect).version(12);
			let mut builder = Builder::new().template(template);

			for source_path in args.split_off(3) {
				let file = fs::File::open(&source_path).unwrap();
				builder.add(file, source_path.as_str()).unwrap();
			}

			builder.dump(target, &BuilderConfig::default()).unwrap();
		}
		cmd => panic!("Unknown sub-command: {}", cmd),
	}
}
