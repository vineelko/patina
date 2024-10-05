//! Module for converting UEFI errors to rusty errors.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

/// A specialized [`Result`](core::result::Result) type for EFI operations.
pub type Result<T> = core::result::Result<T, EfiError>;

use r_efi::efi;
// TODO: Handle difference between warning and error

/// EDK II Error Code equivalent as a Rust Error enum
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EfiError {
    LoadError,
    InvalidParameter,
    Unsupported,
    BadBufferSize,
    BufferTooSmall,
    NotReady,
    DeviceError,
    WriteProtected,
    OutOfResources,
    VolumeCorrupted,
    VolumeFull,
    NoMedia,
    MediaChanged,
    NotFound,
    AccessDenied,
    NoResponse,
    NoMapping,
    Timeout,
    NotStarted,
    AlreadyStarted,
    Aborted,
    IcmpError,
    TftpError,
    ProtocolError,
    IncompatibleError,
    SecurityViolation,
    CrcError,
    EndOfMedia,
    EndOfFile,
    InvalidLanguage,
    CompromisedData,
    IpAddressConflict,
    HttpError,
}

impl From<EfiError> for efi::Status {
    fn from(e: EfiError) -> efi::Status {
        match e {
            EfiError::LoadError => efi::Status::LOAD_ERROR,
            EfiError::InvalidParameter => efi::Status::INVALID_PARAMETER,
            EfiError::Unsupported => efi::Status::UNSUPPORTED,
            EfiError::BadBufferSize => efi::Status::BAD_BUFFER_SIZE,
            EfiError::BufferTooSmall => efi::Status::BUFFER_TOO_SMALL,
            EfiError::NotReady => efi::Status::NOT_READY,
            EfiError::DeviceError => efi::Status::DEVICE_ERROR,
            EfiError::WriteProtected => efi::Status::WRITE_PROTECTED,
            EfiError::OutOfResources => efi::Status::OUT_OF_RESOURCES,
            EfiError::VolumeCorrupted => efi::Status::VOLUME_CORRUPTED,
            EfiError::VolumeFull => efi::Status::VOLUME_FULL,
            EfiError::NoMedia => efi::Status::NO_MEDIA,
            EfiError::MediaChanged => efi::Status::MEDIA_CHANGED,
            EfiError::NotFound => efi::Status::NOT_FOUND,
            EfiError::AccessDenied => efi::Status::ACCESS_DENIED,
            EfiError::NoResponse => efi::Status::NO_RESPONSE,
            EfiError::NoMapping => efi::Status::NO_MAPPING,
            EfiError::Timeout => efi::Status::TIMEOUT,
            EfiError::NotStarted => efi::Status::NOT_STARTED,
            EfiError::AlreadyStarted => efi::Status::ALREADY_STARTED,
            EfiError::Aborted => efi::Status::ABORTED,
            EfiError::IcmpError => efi::Status::ICMP_ERROR,
            EfiError::TftpError => efi::Status::TFTP_ERROR,
            EfiError::ProtocolError => efi::Status::PROTOCOL_ERROR,
            EfiError::IncompatibleError => efi::Status::INCOMPATIBLE_VERSION,
            EfiError::SecurityViolation => efi::Status::SECURITY_VIOLATION,
            EfiError::CrcError => efi::Status::CRC_ERROR,
            EfiError::EndOfMedia => efi::Status::END_OF_MEDIA,
            EfiError::EndOfFile => efi::Status::END_OF_FILE,
            EfiError::InvalidLanguage => efi::Status::INVALID_LANGUAGE,
            EfiError::CompromisedData => efi::Status::COMPROMISED_DATA,
            EfiError::IpAddressConflict => efi::Status::IP_ADDRESS_CONFLICT,
            EfiError::HttpError => efi::Status::HTTP_ERROR,
        }
    }
}
