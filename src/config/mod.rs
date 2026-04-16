//! YAML-based configuration loading and schema definitions.
//!
//! Reads `parallax.yaml` (or a custom path), deserializes it into
//! [`schema::PlatformConfig`], and constructs the evaluator chain.

pub mod loader;
pub mod schema;
