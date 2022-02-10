// Fundamental modules
mod app;
mod commands;
mod keys;
mod utils;

// NOTE: Unwrapping in a CLI is a no-no. Since throwing Rust developer errors at average users is mental overload
fn main() {
	pretty_env_logger::init();
	use keys::key_names;

	// Build CLI
	let keys = keys::build_keys();
	let app = app::build_app(keys);
	let commands = commands::build_commands();

	// Start CLI
	let matches = app.get_matches();

	if matches.is_present(key_names::QUIET) {
		std::env::set_var("RUST_LOG", "error");
	};

	let res = match matches.subcommand() {
		Some((key, mtx)) => commands.get(key).unwrap().evaluate(mtx),
		None => {
			log::info!("vach-cli: Run `vach --help` for usage");
			Ok(())
		},
	};

	if let Err(err) = res {
		log::error!("{}", err)
	};
}
