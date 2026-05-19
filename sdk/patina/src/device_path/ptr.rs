//! UEFI device path pointer newtype.

use r_efi::efi;

/// A validated, non-null pointer to a UEFI [`device_path::Protocol`] structure.
///
/// This newtype concentrates the safety invariant for raw device path pointers at
/// construction time (via the [`unsafe fn new()`](DevicePathPtr::new) and
/// [`unsafe fn from_raw()`](DevicePathPtr::from_raw) constructors), allowing
/// functions that receive a `DevicePathPtr` to be declared safe.
///
/// `DevicePathPtr` is [`Copy`] since it is just a pointer value — callers are
/// responsible for ensuring that the underlying memory remains valid for the
/// lifetime of every copy.
///
/// [`device_path::Protocol`]: r_efi::efi::protocols::device_path::Protocol
#[derive(Copy, Clone)]
pub struct DevicePathPtr(*mut efi::protocols::device_path::Protocol);

// SAFETY: Device path structures reside in firmware-owned memory that is not
// mutated through this wrapper. In UEFI's cooperative single-threaded execution
// model it is safe to send and share this pointer across task boundaries.
unsafe impl Send for DevicePathPtr {}
// SAFETY: See `Send` impl above.
unsafe impl Sync for DevicePathPtr {}

impl DevicePathPtr {
    /// Creates a `DevicePathPtr` from a raw non-null pointer.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `ptr` is non-null and points to a valid,
    /// well-formed UEFI device path structure that remains readable for the
    /// lifetime of any use of the returned `DevicePathPtr`.
    pub unsafe fn new(ptr: *mut efi::protocols::device_path::Protocol) -> Self {
        debug_assert!(!ptr.is_null(), "DevicePathPtr::new called with null pointer");
        // SAFETY: caller guarantees ptr is non-null and valid.
        Self(ptr)
    }

    /// Converts a nullable raw pointer to `Option<DevicePathPtr>`, returning
    /// `None` if `ptr` is null.
    ///
    /// # Safety
    ///
    /// Same contract as [`new`](Self::new): if `ptr` is non-null it must point to
    /// a valid, well-formed UEFI device path structure that remains readable for
    /// the lifetime of any use of the returned `DevicePathPtr`.
    pub unsafe fn from_raw(ptr: *mut efi::protocols::device_path::Protocol) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: ptr is non-null; caller guarantees validity per this function's contract.
            Some(unsafe { Self::new(ptr) })
        }
    }

    /// Returns the underlying raw pointer.
    pub fn as_ptr(self) -> *mut efi::protocols::device_path::Protocol {
        self.0
    }

    /// Returns `true` if this pointer refers to an end-of-device-path node.
    pub fn is_end(self) -> bool {
        // SAFETY: DevicePathPtr guarantees the pointer is non-null and valid.
        let node = unsafe { &*self.0 };
        node.r#type == efi::protocols::device_path::TYPE_END
            && node.sub_type == efi::protocols::device_path::End::SUBTYPE_ENTIRE
    }
}
