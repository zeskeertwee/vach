#![allow(unused)]

pub(crate) mod global;
pub(crate) mod loader;
pub(crate) mod writer;

// run the tests using the command "cargo test -- --nocapture" to see log output
// log level is set to trace if RUST_LOG is not set
#[cfg(test)]
mod tests;