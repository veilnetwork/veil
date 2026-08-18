//! Owner-only NTFS DACLs for the files that carry a bearer secret.
//!
//! POSIX spells "only my account may read this" as `chmod 0o600`. Windows has
//! no equivalent bit: a file created with default security attributes takes
//! whatever DACL the parent directory hands down. Under `%LOCALAPPDATA%` that
//! inheritance is already owner-only, but the runtime directory is not always
//! there — `VEIL_RUNTIME_DIR` is operator-supplied, and the last-resort
//! platform default falls through `%LOCALAPPDATA%` → `%APPDATA%` → `%TEMP%`,
//! which for a service account is `C:\Windows\Temp`, a directory every account
//! on the machine can write into. A 32-byte admin/IPC token inherited into a
//! DACL like that authenticates any other local user to both control planes.
//!
//! Two consequences shape this module:
//!
//! * the DACL is set EXPLICITLY (`PROTECTED_DACL_SECURITY_INFORMATION`, so
//!   inherited entries are dropped rather than merged), on the open handle
//!   rather than by path — the handle names the object we actually wrote, so
//!   no second path resolution can be redirected between write and chmod;
//! * the DACL is then READ BACK. An ACL that cannot be confirmed owner-only is
//!   a refusal, not a warning. A filesystem that carries no ACLs at all (FAT32
//!   on a removable volume, some network redirectors) reports exactly like a
//!   correctly-restricted one once the file is closed, and the caller has no
//!   way to tell them apart afterwards — so "could not confirm" has to stop the
//!   write while the file is still ours to delete.
//!
//! Nothing here is reachable on POSIX; the `0o600`-at-create path is unchanged.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetTokenInformation, NO_INHERITANCE, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::AclVerdict;

/// `ACCESS_ALLOWED_ACE_TYPE`. Declared locally rather than imported so the
/// crate does not pull the whole `Win32_System_SystemServices` namespace in
/// for one byte-wide discriminant.
const ACE_TYPE_ACCESS_ALLOWED: u8 = 0;
/// `ACCESS_DENIED_ACE_TYPE`. A deny entry can only narrow access, so it is the
/// one other type this module is willing to walk past.
const ACE_TYPE_ACCESS_DENIED: u8 = 1;

// ── RAII wrappers ─────────────────────────────────────────────────────────────

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `OpenProcessToken` and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Anything the security APIs allocate with `LocalAlloc` and expect the caller
/// to release — the ACL from `SetEntriesInAclW`, the self-relative descriptor
/// from `GetSecurityInfo`.
struct LocalGuard(*mut c_void);

impl Drop for LocalGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a LocalAlloc'd block owned by this guard.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

// ── owner SID ─────────────────────────────────────────────────────────────────

/// The running process's user SID, copied into a buffer this crate owns.
///
/// Backed by `Vec<u32>` rather than `Vec<u8>`: a `SID` ends in a `DWORD`
/// sub-authority array and the security APIs read it as such, so the buffer has
/// to be 4-byte aligned. A byte vector only guarantees alignment 1.
struct OwnerSid {
    buf: Vec<u32>,
}

impl OwnerSid {
    fn of_current_process() -> io::Result<Self> {
        // SAFETY: every pointer below is either a stack local of the size the
        // call is told about, or a buffer sized by the call's own first pass.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = HandleGuard(token);

            // First pass sizes the buffer and is EXPECTED to fail with
            // ERROR_INSUFFICIENT_BUFFER; only `needed` matters.
            let mut needed: u32 = 0;
            let _ = GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(io::Error::last_os_error());
            }
            // u64 elements so the TOKEN_USER (which holds a pointer) lands
            // aligned for its widest field on both 32- and 64-bit.
            let mut info = vec![0u64; (needed as usize).div_ceil(size_of::<u64>())];
            if GetTokenInformation(
                token.0,
                TokenUser,
                info.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }

            let token_user = &*info.as_ptr().cast::<TOKEN_USER>();
            let sid = token_user.User.Sid;
            let len = GetLengthSid(sid);
            if len == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buf = vec![0u32; (len as usize).div_ceil(size_of::<u32>())];
            if CopySid(len, buf.as_mut_ptr().cast(), sid) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { buf })
        }
    }

    fn as_psid(&self) -> PSID {
        self.buf.as_ptr().cast_mut().cast()
    }
}

// ── ACL construction ──────────────────────────────────────────────────────────

/// Build a one-entry ACL: full control for `sid`, nobody else named at all.
///
/// `inheritance` is `NO_INHERITANCE` for a file and
/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` for the runtime directory, so
/// that a sidecar written by plain `std::fs::write` into that directory still
/// lands owner-only.
fn owner_only_acl(sid: &OwnerSid, inheritance: u32) -> io::Result<LocalGuard> {
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            // With TRUSTEE_IS_SID the name field carries the SID pointer —
            // the documented idiom, not a string.
            ptstrName: sid.as_psid().cast(),
        },
    };
    let mut acl: *mut ACL = null_mut();
    // SAFETY: one entry is described, `entry` outlives the call, and the
    // out-pointer is a stack local.
    let rc = unsafe { SetEntriesInAclW(1, &entry, null(), &mut acl) };
    if rc != ERROR_SUCCESS || acl.is_null() {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(LocalGuard(acl.cast()))
}

// ── read-back ─────────────────────────────────────────────────────────────────

/// Read an object's DACL back and classify it.
///
/// Only two ACE types are understood — allow and deny. Anything else (an
/// object-type ACE, whose SID sits at a different offset) is reported
/// `Unverifiable` rather than decoded at the wrong offset and waved through.
fn verdict_for_handle(handle: HANDLE, sid: &OwnerSid) -> AclVerdict {
    // SAFETY: all out-parameters are stack locals; the descriptor the call
    // allocates is released by `LocalGuard`, and `dacl` points into it, so it
    // stays valid for the whole walk below.
    unsafe {
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let rc = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        );
        if rc != ERROR_SUCCESS {
            return AclVerdict::Unverifiable;
        }
        let _descriptor = LocalGuard(descriptor);

        // A NULL DACL is not "nobody"; it is "everyone, everything".
        if dacl.is_null() {
            return AclVerdict::Shared { foreign_grants: 1 };
        }

        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        if GetAclInformation(
            dacl,
            std::ptr::from_mut(&mut size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return AclVerdict::Unverifiable;
        }

        let mut foreign_grants = 0usize;
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = null_mut();
            if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
                return AclVerdict::Unverifiable;
            }
            let header = &*ace.cast::<ACE_HEADER>();
            match header.AceType {
                // Deny can only narrow; it never hands access to a third party.
                ACE_TYPE_ACCESS_DENIED => continue,
                ACE_TYPE_ACCESS_ALLOWED => {}
                _ => return AclVerdict::Unverifiable,
            }
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let ace_sid: PSID = std::ptr::from_ref(&allowed.SidStart).cast_mut().cast();
            if EqualSid(ace_sid, sid.as_psid()) == 0 {
                foreign_grants += 1;
            }
        }

        if foreign_grants == 0 {
            AclVerdict::OwnerOnly
        } else {
            AclVerdict::Shared { foreign_grants }
        }
    }
}

fn refuse(path_hint: &str, verdict: &AclVerdict) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "refusing to publish a secret at {path_hint}: its access-control list \
             reads back as {verdict:?}, not owner-only — another local account \
             could read it"
        ),
    )
}

// ── crate-facing operations ───────────────────────────────────────────────────

/// Give `file` an explicit owner-only DACL and confirm it took, on the open
/// handle. The handle is the object we wrote; a rename within the volume
/// carries this descriptor with it, so the published file inherits nothing.
pub(crate) fn harden_open_file(file: &std::fs::File, path_hint: &str) -> io::Result<()> {
    let sid = OwnerSid::of_current_process()?;
    let acl = owner_only_acl(&sid, NO_INHERITANCE)?;
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: `handle` is owned by `file` and outlives the call; `acl.0` is a
    // valid ACL for the duration of `acl`.
    let rc = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl.0 as *const ACL,
            null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let verdict = verdict_for_handle(handle, &sid);
    if crate::secret_write_permitted(&verdict) {
        Ok(())
    } else {
        Err(refuse(path_hint, &verdict))
    }
}

/// Re-open `path` and confirm the published file is still owner-only.
///
/// Separate from [`harden_open_file`] because the two answer different
/// questions: that one asks whether the write we staged was restricted, this
/// one asks whether the object now sitting at the published path is.
pub(crate) fn verify_path(path: &Path) -> io::Result<()> {
    let sid = OwnerSid::of_current_process()?;
    let file = std::fs::File::open(path)?;
    let verdict = verdict_for_handle(file.as_raw_handle() as HANDLE, &sid);
    if crate::secret_write_permitted(&verdict) {
        Ok(())
    } else {
        Err(refuse(&path.display().to_string(), &verdict))
    }
}

/// Put an inheritable owner-only DACL on a directory, by path.
///
/// Best-effort at the call sites: a permissive directory cannot leak a file
/// whose own DACL denies the reader, so this narrows the blast radius of a
/// sidecar written without hardening rather than being the gate itself.
pub(crate) fn harden_dir(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    let sid = OwnerSid::of_current_process()?;
    let acl = owner_only_acl(&sid, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)?;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory path contains an interior NUL",
        ));
    }
    wide.push(0);
    // SAFETY: `wide` is NUL-terminated and outlives the call; `acl.0` is a
    // valid ACL for the duration of `acl`.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl.0 as *const ACL,
            null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}
