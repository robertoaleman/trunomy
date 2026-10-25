// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMemoryError {
    NullPointer,
    ZeroLength,
    AddressOverflow,
    NonCanonicalAddress,
    OutsideUserRange,
    UnalignedAddress,
    PageNotMapped,
    PageNotUser,
    PagePermissionDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAccess {
    Read,
    Write,
    Execute,
}

pub const USER_MIN: u64 = 0x0000_0000_0001_0000;
pub const USER_MAX: u64 = 0x0000_7FFF_FFFF_F000;

pub fn validate_user_range(ptr: u64, len: usize) -> Result<(), UserMemoryError> {
    if ptr == 0 {
        return Err(UserMemoryError::NullPointer);
    }
    if len == 0 {
        return Err(UserMemoryError::ZeroLength);
    }

    let len = u64::try_from(len).map_err(|_| UserMemoryError::AddressOverflow)?;
    let end = ptr
        .checked_add(len - 1)
        .ok_or(UserMemoryError::AddressOverflow)?;

    if ptr > USER_MAX || end > USER_MAX {
        return Err(UserMemoryError::OutsideUserRange);
    }
    if ptr < USER_MIN {
        return Err(UserMemoryError::NonCanonicalAddress);
    }

    Ok(())
}

pub fn validate_user_access(ptr: u64, len: usize, access: UserAccess) -> Result<(), UserMemoryError> {
    validate_user_range(ptr, len)?;

    let Some(active_pml4) = crate::memory::current_user_pml4() else {
        return Err(UserMemoryError::PageNotMapped);
    };

    unsafe {
        active_pml4.validate_user_page_range(
            ptr,
            len,
            matches!(access, UserAccess::Write),
            matches!(access, UserAccess::Execute),
        )
    }
    .map_err(|error| match error {
        crate::memory::process_paging::UserPageError::UnalignedAddress => UserMemoryError::UnalignedAddress,
        crate::memory::process_paging::UserPageError::NotMapped => UserMemoryError::PageNotMapped,
        crate::memory::process_paging::UserPageError::NotUserPage => UserMemoryError::PageNotUser,
        crate::memory::process_paging::UserPageError::PermissionDenied => UserMemoryError::PagePermissionDenied,
    })
}

pub fn validate_user_read(ptr: u64, len: usize) -> Result<(), UserMemoryError> {
    validate_user_access(ptr, len, UserAccess::Read)
}

pub fn validate_user_write(ptr: u64, len: usize) -> Result<(), UserMemoryError> {
    validate_user_access(ptr, len, UserAccess::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_user_buffer_is_accepted() {
        assert!(validate_user_range(USER_MIN, 64).is_ok());
    }

    #[test]
    fn null_and_empty_buffers_are_rejected() {
        assert_eq!(validate_user_range(0, 1), Err(UserMemoryError::NullPointer));
        assert_eq!(validate_user_range(USER_MIN, 0), Err(UserMemoryError::ZeroLength));
    }

    #[test]
    fn overflowing_range_is_rejected() {
        assert_eq!(validate_user_range(u64::MAX - 1, 8), Err(UserMemoryError::AddressOverflow));
    }

    #[test]
    fn kernel_and_noncanonical_ranges_are_rejected() {
        assert_eq!(validate_user_range(USER_MIN - 1, 1), Err(UserMemoryError::NonCanonicalAddress));
        assert_eq!(validate_user_range(USER_MAX, 2), Err(UserMemoryError::OutsideUserRange));
    }

    #[test]
    fn page_validation_requires_active_pml4() {
        assert_eq!(validate_user_access(USER_MIN, 64, UserAccess::Read), Err(UserMemoryError::PageNotMapped));
    }
}
