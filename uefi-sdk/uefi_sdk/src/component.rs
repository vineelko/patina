//! Module for creating UEFI components.
//!
//! This module provides a way to create UEFI components by allowing each component to define its own dependencies. The
//! component executor will automatically resolve the dependencies and execute the component.
//!
//! This crate takes its inspiration from the [Entity Component System](https://en.wikipedia.org/wiki/Entity_component_system)
//! architectural pattern, while only using a subset of its described characteristics. This crate's implementation is
//! heavily inspired by the [bevy_ecs](https://crates.io/crates/bevy_ecs) crate, which was created by the [Bevy](https://bevyengine.org/)
//! engine team.
//!
//! This crate comes from the need to design a highly generic and extensible user interface for UEFI driver
//! development. As such, we only need a subset of the features offered by `bevy_ecs`, and thus we pulled out the core
//! functionality from `bevy_ecs` that is applicable to our needs, modified it to fit our use case, and expanded on it.
//!
//! ## Features
//!
//! This module has two main use cases: (1) for end users to write their own components and (2) for the DxeCore to manage
//! these components and their dependencies. (1) is always available, however (2) is only available when the `core`
//! feature flag is enabled.
//!
//! - `core`: Exposes additional items necessary to manage and execute components and their dependencies.
//!
//! ## Creating a Component
//!
//! The only requirement for a component is that it implements the [Component] trait. This trait defines the methods
//! necessary for a component to be executed by the DxeCore. The [Component] trait is public, so it can be implemented
//! by any user-defined type. So long as it implements [IntoComponent], it can be registered with and executed by the
//! DxeCore.
//!
//! This module defines a `FunctionComponent` implementation of a the [Component] trait, whose [IntoComponent]
//! implementation is a blanket implementation for any functions whose parameters implement [Param](params::Param).
//! You can review the [Param](params::Param) implementations for all types that can be used as parameters to these
//! functions. The `FunctionComponent` implementation has an arbitrary parameter count limit of 5, but this can be
//! changed in the future if needed. See the [params] module for more information.
//!
//! ### `Param` types
//!
//! Below is a list of all types that implement the [Param](params::Param) trait, within this crate. Other
//! implementations may still exist.
//!
//! | Param                        | Description                                                                                                                                                |
//! |------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
//! | Option\<P\>                  | An Option, where P implements `Param`. Allows components to run even when the underlying parameter is unavailable. See the [params] module for more info.  |
//! | (P1, P2, ...)                | A Tuple where each entry implements `Param`. Useful when you need more parameters than the current parameter limit. See the [params] module for more info. |
//! | Config\<T\>                  | An immutable config value that will only be available once the underlying data has been locked. See The [params] module for more info.                     |
//! | ConfigMut\<T\>               | A mutable config value that will only be available while the underlying data is unlocked. See the [params] module for more info.                           |
//! | &HobList                     | An immutable reference to a list of Handoff Blocks (HOBs) passed to the DXE Core.                                                                          |
//! | StandardBootServices         | Rust implementation of Boot Services                                                                                                                       |
//!
//! ### Example
//!
//! ```rust
//! # use uefi_sdk::{error::Result, component::params::ConfigMut};
//! # use mu_pi::hob::HobList;
//! fn my_driver(hob_list: &HobList, mut config: ConfigMut<u32>) -> Result<()>{
//!     for hob in hob_list {
//!         // Find the hob(s) that I care about, set the config value
//!         *config = 42;
//!
//!         // Lock it so any `Config<u32>` components can be executed. They will not
//!         // execute until the config is locked.
//!         config.lock();
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
extern crate alloc;

mod function_component;
mod struct_component;
mod metadata;
pub mod params;
mod storage;

#[cfg(any(feature = "doc", feature = "core"))]
pub use metadata::MetaData;
#[cfg(any(feature = "doc", feature = "core"))]
pub use storage::{Storage, UnsafeStorageCell};

use crate::error::Result;

/// An executable object whose parameters implement [Param](params::Param).
pub trait Component {
    /// Runs the component when it does not have exclusive access to the storage.
    ///
    /// Components that run in parallel do not have exclusive access to the storage and thus must be executed using the
    /// this method.
    ///
    /// ## Safety
    ///
    /// - Each parameter must properly register its access, so the scheduler can ensure that there are no data
    ///   conflicts in [Params](params::Param) for parallel execution of components. See [Param::init_state](params::Param::init_state)
    ///   for more information on how to properly register parameter access.
    unsafe fn run_unsafe(&mut self, storage: storage::UnsafeStorageCell) -> Result<bool>;

    /// Runs the component with exclusive access to the storage.
    fn run(&mut self, storage: &mut storage::Storage) -> Result<bool> {
        storage.apply_deferred();
        let storage_cell = storage::UnsafeStorageCell::from(storage);
        // SAFETY: This is safe because this component has exclusive access to the storage.
        unsafe { self.run_unsafe(storage_cell) }
    }

    /// One-time initialization of the component. This is where parameter access requirements should be registered in
    /// the metadata of the component. The scheduler uses this metadata when scheduling components in a multi-threaded
    /// context. Typically this method will pass the metadata to each parameter to register its access requirements,
    /// but that is not a requirement.
    fn initialize(&mut self, storage: &mut storage::Storage);

    /// Returns the metadata of the component. used in a multi-threaded context to schedule components.
    fn metadata(&self) -> &metadata::MetaData;
}

/// A helper trait to convert an object into a [Component].
pub trait IntoComponent<Input> {
    fn into_component(self) -> alloc::boxed::Box<dyn Component>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::error::{EfiError, Result};
    use mu_pi::hob::HobList;

    use super::*;

    // This component should run no problem.
    fn example_component_success() -> Result<()> {
        Ok(())
    }

    // HobList should be empty, so `validate_param` should fail and the component
    // should not run.
    fn example_component_not_dispatched(_hob_list: &HobList) -> Result<()> {
        Ok(())
    }

    fn example_component_fail() -> Result<()> {
        Err(EfiError::Aborted)
    }

    #[test]
    fn test_component_run_return_handling_in_core_pre_memory_init_add_component() {
        let mut storage = storage::Storage::new();

        // Test component dispatched and succeeds does not panic does not panic and returns Ok(true)
        let mut component1 = example_component_success.into_component();
        component1.initialize(&mut storage);
        assert!(component1.run(&mut storage).is_ok_and(|res| res));

        // Test component not dispatched does not panic and returns Ok(false)
        let mut component2 = example_component_not_dispatched.into_component();
        component2.initialize(&mut storage);
        assert!(component2.run(&mut storage).is_ok_and(|res| !res));

        // Test component failed does not panic and returns Err(EfiError::<Something>)
        let mut component3 = example_component_fail.into_component();
        component3.initialize(&mut storage);
        assert!(component3.run(&mut storage).is_err_and(|res| res == EfiError::Aborted));
    }
}
