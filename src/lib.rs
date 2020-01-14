#[macro_use]
extern crate derive_more;
#[macro_use]
extern crate serde_derive;

pub use spf::*;

mod spf;
#[cfg(fuzzing)]
pub mod fuzz;