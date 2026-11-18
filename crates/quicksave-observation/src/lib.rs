// SPDX-License-Identifier: GPL-3.0-only
//! Scope-confined native process/open-file evidence, never backup authority.
//!
//! See README.md for the immutable No Land source provenance and CAPABILITIES.md
//! for what each runtime adapter actually guarantees. No payloads are read.
#![deny(unsafe_op_in_unsafe_fn)]

mod engine;
pub mod integration;
mod model;
pub mod native;
mod polling;
mod scope;
mod worker;

pub use engine::ObservationEngine;
pub use model::*;
pub use native::native_source;
pub use polling::{DescriptorSample, PollingSource, ProbeListing, ProcessDescriptor, ProcessProbe};
pub use scope::{
    ApplicationSpec, MacBundleBinding, NativeApplicationSpec, ObservationRootKind,
    ObservationScope, RootSpec, ScopeConsent, ScopeRequest,
};
pub use worker::{ObservationCallback, ObservationWorker, WorkerConfig};

#[cfg(test)]
mod tests;
