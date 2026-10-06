//! `MmSupervisorCore` Method Implementations
//!
//! The inherent methods of [`MmSupervisorCore`](crate::MmSupervisorCore), split by the lifecycle
//! phase they belong to rather than by the data they touch:
//!
//! - [`entry`] — construction and the MM entry point every core arrives through
//! - [`init`] — the one-time setup a core runs on its first entry
//! - [`runtime`] — the dispatch loop and AP holding pen used on every later entry
//!
//! `entry_point` decides which of the other two a given core needs, so the three modules form a
//! sequence rather than a hierarchy and do not call sideways into each other.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

pub(crate) mod entry;
pub(crate) mod init;
pub(crate) mod runtime;
