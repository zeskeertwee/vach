// Fundamental modules
mod commands;
mod keys;
mod utils;
mod app;

// NOTE: Unwrapping in a CLI is a no-no. Since throwing Rust developer errors at average users is mental overload
fn main() {
	use keys::key_names;

	let keys = keys::build_keys();
	let app = app::build_app(keys);
	let matches = app.get_matches();

	if matches.is_present(key_names::QUIET) {
		std::env::set_var("RUST_LOG", "error");
	};

	let res = match matches.subcommand() {
		 ("keypair", Some(mtx)) => { commands::KEYPAIR_COMMAND.evaluate(mtx) },
		 ("split", Some(mtx)) => { commands::SPLIT_COMMAND.evaluate(mtx) },
		 ("verify", Some(mtx)) => { commands::VERIFY_COMMAND.evaluate(mtx) },
		 ("list", Some(mtx)) => { commands::LIST_COMMAND.evaluate(mtx) },
		 ("pack", Some(mtx)) => { commands::PACK_COMMAND.evaluate(mtx) },
		 ("unpack", Some(mtx)) => { commands::UNPACK_COMMAND.evaluate(mtx) },
		 (cmd, _) => panic!("Unknown command, {}", cmd)
	};

	if let Err(err) = res {
		 println!("Error: {}", err)
	};
}
