mod commands;
mod config;
mod keys;
mod utils;
mod app;

use config::Mode;
use log::error;
use std::env;

// NOTE: Unwrapping in a CLI is a no-no. Since throwing Rust developer errors at average users is mental overload
fn main() {
	use keys::key_names;

	let keys = keys::build_keys();
	let app = app::build_app(keys);
	let matches = app.get_matches();

	if matches.is_present(key_names::QUIET) {
		env::set_var("RUST_LOG", "info");
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

	res.unwrap();

	// // Initialization
	// pretty_env_logger::init();

	// let mut config = match config::Config::from_args() {
	// 	Ok(x) => x,
	// 	Err(e) => {
	// 		error!("An error occurred while parsing the command: {}", e);
	// 		return;
	// 	}
	// };

	// let config_mode = config.mode.clone();

	// let res = match config_mode {
	// 	Mode::None => {
	// 		error!("No action specified!");
	// 		return;
	// 	}
	// 	Mode::Error { msg } => {
	// 		error!("An error occurred while parsing the command: {}", msg);
	// 		return;
	// 	}
	// 	Mode::GenKeypair { save_folder: _ } => Ok(()),
	// 	Mode::Open { archive, save_path } => {
	// 		commands::unpack::handle_open_command(&config, archive, save_path)
	// 	}
	// 	Mode::Package {
	// 		files,
	// 		save_path,
	// 		compress_mode,
	// 		encrypt,
	// 	} => commands::pack::handle_package_command(
	// 		&mut config,
	// 		files,
	// 		save_path,
	// 		compress_mode,
	// 		encrypt,
	// 	),
	// };

	// match res {
	// 	Ok(_) => (),
	// 	Err(e) => error!("An error occurred while executing the command: {}", e),
	// }
}
