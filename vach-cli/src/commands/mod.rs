const PROGRESS_BAR_STYLE: &str = "{wide_bar} {pos:>7}/{len:7} ETA {eta_precise}";

mod keypair;
pub use keypair::handle_keypair_command;

mod open;
pub use open::handle_open_command;

mod package;
pub use package::handle_package_command;
