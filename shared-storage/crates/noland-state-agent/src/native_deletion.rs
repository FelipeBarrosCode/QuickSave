// SPDX-License-Identifier: GPL-3.0-only
//! Read-only Rust projection of an actual authenticated, frozen source plan.
//! Derived integration: No Land e81238a7536aae201540956ce76981364fd36595.

use crate::StateAgent;
use noland_state_core::{Result, StateError};
use noland_storage::FullDeletionPlan;
use uuid::Uuid;

impl StateAgent {
    /// This is a native Rust closure, not renderer JSON. Project identities
    /// without cloning all pack metadata just to describe dependencies.
    pub fn native_with_deletion_plan<T>(
        &self,
        id: Uuid,
        project: impl FnOnce(&FullDeletionPlan) -> Result<T>,
    ) -> Result<T> {
        if !self.config.native_host || self.config.converge_complete_backups {
            return Err(StateError::Invalid(
                "native deletion projection requires additive native mode".into(),
            ));
        }
        let plan = self.deletion_plan.lock();
        let plan = plan.as_ref().filter(|plan| plan.id == id).ok_or_else(|| {
            StateError::Conflict("the original frozen deletion preview is unavailable".into())
        })?;
        plan.validate("cloud", plan.binding.as_deref())?;
        let full = plan
            .cloud
            .as_ref()
            .ok_or_else(|| StateError::Invalid("not a cloud deletion plan".into()))?;
        if full.plan_id != id || full.automatic {
            return Err(StateError::Invalid(
                "automatic generation retirement is not native authority".into(),
            ));
        }
        project(full)
    }
}
