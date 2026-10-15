//! HOB Lookup Helpers
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use patina::pi::hob::{self, Hob, PhaseHandoffInformationTable};

/// Finds the first memory allocation module HOB matching both names.
///
/// A module is identified by two GUIDs: `allocation_name` is the allocation descriptor's name,
/// which says which producer reserved the pages, and `module_name` identifies the image occupying
/// them. Both must match, because the same image is described by different allocation names
/// depending on who allocated it.
///
/// Returns `None` when no HOB matches both.
pub(crate) fn find_module<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    allocation_name: patina::BinaryGuid,
    module_name: patina::BinaryGuid,
) -> Option<&'a hob::MemoryAllocationModule> {
    for current_hob in hobs {
        if let Hob::MemoryAllocationModule(module) = current_hob
            && module.alloc_descriptor.name == allocation_name
            && module.module_name == module_name
        {
            log::info!(
                "Found MM module {module_name:?}: entry_point=0x{:016x}, base=0x{:016x}, size=0x{:x}",
                module.entry_point,
                module.alloc_descriptor.memory_base_address,
                module.alloc_descriptor.memory_length
            );
            return Some(module);
        }
    }

    None
}

/// Finds the first GUID HOB matching `target_guid` and returns its data slice.
///
/// Returns `None` if no matching HOB is found.
pub(crate) fn find_guid_hob(
    hob_list_info: &PhaseHandoffInformationTable,
    target_guid: patina::BinaryGuid,
) -> Option<&[u8]> {
    for current_hob in &Hob::Handoff(hob_list_info) {
        if let Hob::GuidHob(guid_hob, data) = current_hob
            && guid_hob.name == target_guid
        {
            return Some(data);
        }
    }
    None
}
