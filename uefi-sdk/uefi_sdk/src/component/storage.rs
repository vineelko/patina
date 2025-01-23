//! A storage container for all datums that can be retrieved via dependency injection.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
extern crate alloc;

use crate::component::{metadata::MetaData, params::Param};

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::{
    any::{Any, TypeId},
    cell::{Ref, RefCell, RefMut, UnsafeCell},
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr,
    sync::atomic::AtomicPtr,
};
use mu_pi::hob::HobList;
use r_efi::efi::BootServices;

/// A vector whose elements are sparsely populated.
#[derive(Debug)]
pub(crate) struct SparseVec<V> {
    values: Vec<Option<V>>,
}

impl<V> SparseVec<V> {
    /// Creates a new empty [SparseVec].
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    #[inline]
    /// Returns true if the [SparseVec] contains a value at the given index.
    pub fn contains(&self, index: usize) -> bool {
        self.values.get(index).map(|v| v.is_some()).unwrap_or(false)
    }

    #[inline]
    /// Returns the value at the given index, if it exists.
    pub fn get(&self, index: usize) -> Option<&V> {
        self.values.get(index).map(|v| v.as_ref()).unwrap_or(None)
    }

    #[inline]
    /// Inserts a value at the given index.
    pub fn insert(&mut self, index: usize, value: V) {
        if index >= self.values.len() {
            self.values.resize_with(index + 1, || None);
        }
        self.values[index] = Some(value);
    }
}

impl<'a, V> IntoIterator for &'a SparseVec<V> {
    type Item = &'a Option<V>;
    type IntoIter = core::slice::Iter<'a, Option<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a, V> IntoIterator for &'a mut SparseVec<V> {
    type Item = &'a mut Option<V>;
    type IntoIter = core::slice::IterMut<'a, Option<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

/// A container for an untyped config datum.
pub struct ConfigRaw(bool, Box<dyn Any>);

impl Debug for ConfigRaw {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigRaw").field("is_locked", &self.0).field("raw_config", &self.1).finish()
    }
}

impl ConfigRaw {
    /// Creates a new [ConfigRaw] object.
    pub fn new(locked: bool, config: Box<dyn Any>) -> Self {
        Self(locked, config)
    }

    /// Locks the config, making it immutable.
    pub fn lock(&mut self) {
        self.0 = true;
    }

    /// Unlocks the config, making it mutable.
    pub(crate) fn unlock(&mut self) {
        self.0 = false;
    }

    /// Returns true if the config is locked.
    pub fn is_locked(&self) -> bool {
        self.0
    }
}

impl Deref for ConfigRaw {
    type Target = dyn Any;

    fn deref(&self) -> &Self::Target {
        self.1.as_ref()
    }
}

impl DerefMut for ConfigRaw {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.1.as_mut()
    }
}

/// Storage container for all datums that can be consumed by a Component.
///
/// The [Component](crate::component::Component) trait provides the interface that a component must implement to be
/// executed by a scheduler. By reviewing the [run](crate::component::Component::run) method, it can be seen that
/// the only data passed to a component during execution is the [Storage] object. This design point was chosen as it
/// eliminates breaking changes when implementing new [Params](crate::component::params::Param). Instead of changing
/// the `Component` trait interface to pass in new data when a new param is added, we can instead updating the
/// [Storage] object to either hold new data, or a reference to new data.
///
/// The expectation is that when a new `Param` is implemented for the SDK, any necessary changes can be made to the
/// [Storage] object, and the [Component](crate::component::Component) trait will not need to be updated. The
/// *breaking* change will occur in the DXE Core itself when consuming the update, it will have the responsibility of
/// providing the new data to the [Storage] object.
///
/// ## Storage as a Param
///
/// The [Storage] object itself implements the [Param] trait so that it can be provided to any component that requests
/// it. Directly accessing the [Storage] object in a component used to make changes to the underlying storage that
/// require exclusive access to the storage. Examples of this is inserting or removing data from storage, as this can
/// invalidate any references to data in the [Storage] object.
#[derive(Debug)]
pub struct Storage {
    /// A container for all [Config](super::params::Config) and [ConfigMut](super::params::ConfigMut) datums. This
    /// resource can be accessed both immutably and mutably, so it must be tracked by
    /// [Access](super::metadata::Access).
    configs: SparseVec<RefCell<ConfigRaw>>,
    /// A map to convert from a TypeId to a config index.
    config_indices: BTreeMap<TypeId, usize>,
    /// The platform's [HobList].
    pub hob_list: HobList<'static>,
    /// A pointer to the UEFI Boot Services Table.
    bs: AtomicPtr<BootServices>,
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage {
    pub const fn new() -> Self {
        Self {
            configs: SparseVec::new(),
            config_indices: BTreeMap::new(),
            hob_list: HobList::new(),
            bs: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Applies all deferred actions to the storage. Used in a multi-threaded context
    pub fn apply_deferred(&self) {
        // TODO
    }

    /// Returns a reference to the platform's [HobList].
    pub fn hob_list(&self) -> &HobList<'static> {
        &self.hob_list
    }

    /// Stores a pointer to the UEFI Boot Services Table.
    pub fn set_boot_services(&self, bs: *mut BootServices) {
        self.bs.store(bs, core::sync::atomic::Ordering::SeqCst);
    }

    /// Returns a pointer to the UEFI Boot Services Table.
    pub fn boot_services(&self) -> *mut BootServices {
        self.bs.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// Registers a config type with the storage and returns its global id.
    pub(crate) fn register_config<C: Default + 'static>(&mut self) -> usize {
        self.get_or_register_config(TypeId::of::<C>())
    }

    /// Gets the global id of a config, registering it if it does not exist.
    pub(crate) fn get_or_register_config(&mut self, id: TypeId) -> usize {
        let idx = self.config_indices.len();
        *self.config_indices.entry(id).or_insert(idx)
    }

    /// Adds a config datum to the storage, overwriting an existing value if it exists.
    pub fn add_config<C: Default + 'static>(&mut self, config: C) {
        let id = self.register_config::<C>();
        self.configs.insert(id, RefCell::new(ConfigRaw::new(false, Box::new(config))));
    }

    /// Gets an immutable reference to a config datum in the storage.
    pub fn try_get_config<C: Default + 'static>(&self) -> Option<crate::component::params::Config<C>> {
        let id = self.config_indices.get(&TypeId::of::<C>())?;
        let untyped = self.get_raw_config(*id);
        Some(crate::component::params::Config::from(untyped))
    }

    /// Gets a mutable reference to a config datum in the storage.
    pub fn try_get_config_mut<C: Default + 'static>(&mut self) -> Option<crate::component::params::ConfigMut<C>> {
        let id = self.config_indices.get(&TypeId::of::<C>())?;
        let untyped = self.get_raw_config_mut(*id);
        Some(crate::component::params::ConfigMut::from(untyped))
    }

    /// Adds a config datum to the storage if one does not already exist.
    ///
    /// Returns true if the config was added, false if it already exists.
    pub(crate) fn try_add_config_with_id<C: Default + 'static>(&mut self, id: usize, config: C) -> bool {
        // Add new config if it does not exist.
        if self.configs.contains(id) {
            return false;
        }
        self.configs.insert(id, RefCell::new(ConfigRaw::new(true, Box::new(config))));
        true
    }

    /// Retrieves a config from the storage.
    pub(crate) fn get_raw_config(&self, id: usize) -> Ref<ConfigRaw> {
        self.configs
            .get(id)
            .unwrap_or_else(|| panic!("Could not find Config value when with id [{}] it should always exist.", id))
            .borrow()
    }

    /// Retrieves a mutable config from the storage.
    pub(crate) fn get_raw_config_mut(&self, id: usize) -> RefMut<ConfigRaw> {
        self.configs
            .get(id)
            .unwrap_or_else(|| panic!("Could not find Config value when with id [{}] it should always exist.", id))
            .borrow_mut()
    }

    /// Unlocks a config in the storage.
    pub(crate) fn unlock_config(&self, id: usize) {
        if let Some(config) = self.configs.get(id) {
            config.borrow_mut().unlock();
        }
    }

    /// Marks all configs present in the storage as locked (immutable).
    pub fn lock_configs(&self) {
        (&self.configs).into_iter().flatten().for_each(|config| config.borrow_mut().lock());
    }
}

/// A wrapper around a reference to a [Storage] object that allows for unsafe mutable
/// access to the storage.
///
/// ## Safety
///
/// - The caller must ensure that no simultaneous conflicting access to the storage occurs.
/// - The caller must ensure exclusive access to the storage when making structural changes.
#[derive(Copy, Clone)]
pub struct UnsafeStorageCell<'s>(*mut Storage, PhantomData<(&'s Storage, &'s UnsafeCell<Storage>)>);

unsafe impl Send for UnsafeStorageCell<'_> {}
unsafe impl Sync for UnsafeStorageCell<'_> {}

impl<'s> From<&'s mut Storage> for UnsafeStorageCell<'s> {
    fn from(storage: &'s mut Storage) -> Self {
        UnsafeStorageCell::new_mutable(storage)
    }
}

impl<'s> From<&'s Storage> for UnsafeStorageCell<'s> {
    fn from(storage: &'s Storage) -> Self {
        UnsafeStorageCell::new_readonly(storage)
    }
}

impl<'s> UnsafeStorageCell<'s> {
    /// Creates a [UnsafeStorageCell] that can be used to access everything immutably.
    #[inline]
    pub fn new_readonly(storage: &'s Storage) -> Self {
        Self(ptr::from_ref(storage).cast_mut(), PhantomData)
    }

    /// Creates a [UnsafeStorageCell] that can be used to access everything mutably.
    #[inline]
    pub fn new_mutable(storage: &'s mut Storage) -> Self {
        Self(ptr::from_mut(storage), PhantomData)
    }

    /// Gets a mutable reference to the [Storage] this [UnsafeStorageCell] wraps.
    ///
    /// This is an incredibly error-prone operation is only valid in a small number of
    /// circumstances.
    ///
    /// ## Safety
    ///
    /// - `self` must have been obtained from a call to [UnsafeStorageCell::new_mutable]
    ///   (*not* `as_unsafe_storage_cell_readonly` or any other method of contruction that does not
    ///   provide mutable access to the entire storage).
    ///   - This means that if you have an [UnsafeStorageCell] that you did not create yourself, it
    ///     is likely *unsound* to call this method.
    /// - The returned `&mut Storage` *must* by unique: it must never be allowed to exists at the
    ///   same time as any other borrows of the storage or any accesses to its data.
    ///   - `&mut Storage` *may* exist at the same time as instances of `UnsafeStorageCell`, so
    ///      long as none of those instances are used to access storage data in any way while the
    ///      mutable borrow is active.
    #[inline]
    pub unsafe fn storage_mut(self) -> &'s mut Storage {
        // Safety:
        // - caller ensures the created `&mut Storage` is the only borrow of the storage.
        unsafe { &mut *self.0 }
    }

    /// Gets a reference to the [Storage] this [UnsafeStorageCell] wraps.
    ///
    /// This can be used for arbitrary shared/readonly access.
    ///
    /// ## Safety
    ///
    /// - must have permission to access the whole storage immutably
    /// - there must be no live exclusive borrows on storage data
    /// - there must be no live exclusive borrow of storage
    #[inline]
    pub unsafe fn storage(self) -> &'s Storage {
        // Safety:
        // - caller ensures there is no `&mut Storage`
        // - caller ensures there is no mutable borrows of storage data. This means the caller
        //   cannot misuse the returned `&World`.
        unsafe { &*self.0 }
    }
}

unsafe impl Param for &mut Storage {
    type State = ();
    type Item<'storage, 'state> = &'storage mut Storage;

    unsafe fn get_param<'storage, 'state>(
        _state: &'state Self::State,
        storage: UnsafeStorageCell<'storage>,
    ) -> Self::Item<'storage, 'state> {
        storage.storage_mut()
    }

    fn validate(_state: &Self::State, _storage: UnsafeStorageCell) -> bool {
        // Always available
        true
    }

    fn init_state(_storage: &mut Storage, meta: &mut MetaData) -> Self::State {
        // Storage provides global access to configuration. That means by manipulating the storage,
        // we can invalidate any config access, so we make sure no other config access has been
        // registered, and set ourselves as exclusive.
        assert!(
            !meta.access().has_any_config_write(),
            "&mut Storage in system {} conflicts with a previous ConfigMut<T> access.",
            meta.name()
        );

        assert!(
            !meta.access().has_any_config_read(),
            "&mut Storage in system {} conflicts with a previous Config<T> access.",
            meta.name()
        );
        meta.access_mut().writes_all_configs();
    }
}

unsafe impl Param for &Storage {
    type State = ();
    type Item<'storage, 'state> = &'storage Storage;

    unsafe fn get_param<'storage, 'state>(
        _state: &'state Self::State,
        storage: UnsafeStorageCell<'storage>,
    ) -> Self::Item<'storage, 'state> {
        storage.storage()
    }

    fn validate(_state: &Self::State, _storage: UnsafeStorageCell) -> bool {
        // Always available
        true
    }

    fn init_state(_storage: &mut Storage, meta: &mut MetaData) -> Self::State {
        assert!(
            !meta.access().has_any_config_write(),
            "&mut Storage in system {} conflicts with a previous ConfigMut<T> access.",
            meta.name()
        );

        meta.access_mut().reads_all_configs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_iter_works() {
        let mut v: SparseVec<u32> = SparseVec::new();

        v.insert(4, 100);
        v.insert(9, 200);
        v.insert(75, 300);

        assert_eq!(v.into_iter().filter(|o| o.is_some()).count(), 3);

        // Check that interior mutability sticks
        for v in &mut v {
            if let Some(v) = v.as_mut() {
                *v += 1;
            }
        }

        assert_eq!(v.get(4), Some(&101));
        assert_eq!(v.get(9), Some(&201));
        assert_eq!(v.get(75), Some(&301));

        // Check that exterior mutability sticks
        for v in &mut v {
            *v = None;
        }

        assert_eq!(v.into_iter().filter(|o| o.is_some()).count(), 0);
    }
}
