// Fundamental modules
mod app;
mod commands;
mod keys;
mod utils;

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
		Some(("keypair", mtx)) => commands::KEYPAIR_COMMAND.evaluate(mtx),
		Some(("split", mtx)) => commands::SPLIT_COMMAND.evaluate(mtx),
		Some(("verify", mtx)) => commands::VERIFY_COMMAND.evaluate(mtx),
		Some(("list", mtx)) => commands::LIST_COMMAND.evaluate(mtx),
		Some(("pack", mtx)) => commands::PACK_COMMAND.evaluate(mtx),
		Some(("unpack", mtx)) => commands::UNPACK_COMMAND.evaluate(mtx),
		Some((_, _)) => Ok(()),
		None => {
			println!("vach-cli: Run `vach --help` for usage");
			Ok(())
		}
	};

	if let Err(err) = res {
		println!("Error: {}", err)
	};
}
