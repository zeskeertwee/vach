use super::error::InternalError;

/// Internal `Result` type alias used by `vach`. Basically equal to: `Result<T, InternalError>`
pub type InternalResult<T> = Result<T, InternalError>;
