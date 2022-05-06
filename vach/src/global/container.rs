/// Containers that allows for shared mutability, either thread-safe or single threaded

#[cfg(feature = "multithreaded")]
use std::sync::Mutex;
#[cfg(feature = "multithreaded")]
use std::sync::Arc;
#[cfg(feature = "multithreaded")]
pub(crate) type Container<T> = Arc<Mutex<T>>;

#[cfg(not(feature = "multithreaded"))]
use std::cell::RefCell;
#[cfg(not(feature = "multithreaded"))]
pub(crate) type Container<T> = RefCell<T>;
