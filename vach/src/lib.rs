#![allow(unused)]

pub mod global;
pub mod loader;
pub mod writer;

// run the tests using the command "cargo test -- --nocapture" to see log output
// log level is set to trace if RUST_LOG is not set
#[cfg(test)]
mod tests;