//! Ephemeral SQLite runtime database. Not the durable source of truth.
//!
//! `StateDb::open_native` selects the admitted native Unix or Windows VFS.
//! Native file pins outlive both connections; every writer/monitoring lock
//! revalidates the actual file identities. Windows verifies protected DACLs,
//! full 128-bit IDs, persistent WAL and FULL synchronization rather than using
//! the ordinary `open` path as a successful private/durable fallback.

mod checkpoint;
mod metadata_cache;
mod monitoring;
mod persistence;
mod projections;
mod restore;
mod schema;
mod store;

pub use checkpoint::LearnedCheckpointGeneration;
pub use metadata_cache::CachedMetadata;
pub use monitoring::OperationMonitoringSnapshot;
pub use store::{DbContentionSnapshot, RestoredPathAssociationInput, StateDb};

pub const SCHEMA_VERSION: i64 = 7;

#[cfg(test)]
mod verification_index_tests;
