//! Reading a path's owner and permissions from the OBJECT, not from its name.
//!
//! The question this answers is asked before an executable is elevated: can an
//! ordinary user rewrite this file, or any directory above it? Getting the
//! answer from a NAME is how it goes wrong, twice over:
//!
//!  * the name is looked up once to read the permissions and again to use the
//!    file, and anything may happen in between — the ordinary time-of-check
//!    hole;
//!  * a name can traverse a junction. `C:\Program Files\xVeil` may be a
//!    reparse point to a directory the user owns, and the permissions read
//!    through it are the TARGET's, which say nothing about who can swap the
//!    link.
//!
//! So this opens the path once and answers everything from that one handle:
//!
//!  * `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`, so a reparse point is
//!    opened AS ITSELF rather than followed. If the object turns out to be
//!    one, that is reported and nothing further is claimed about it — a link
//!    in the chain is a refusal, not something to resolve and carry on;
//!  * `GetFinalPathNameByHandleW`, so the caller can see what the name it
//!    asked about actually resolved to;
//!  * `GetSecurityInfo` — the HANDLE-based call. Its named twin,
//!    `GetNamedSecurityInfo`, takes a path and looks it up again, which is
//!    precisely the thing being got rid of.
//!
//! What was here before was PowerShell `Get-Acl` per path, and its own comment
//! said what it was: the part of the fix that could be written without a
//! Windows host to verify on. There is a host now (report24 / audit C-01).
//!
//! Facts only. Every judgement — which SIDs count as privileged, which rights
//! are fatal for which role — stays on the Dart side, where the whole matrix
//! is exercised without a filesystem. This returns the same JSON shape that
//! side already parses, so nothing about the decision moved.

use std::ffi::c_char;
use std::ffi::c_int;

use crate::{VEIL_ERR, VEIL_OK, write_err};

/// What this probe may conclude from an ACE of a given type.
///
/// The probe reads a plain mask at a fixed offset, which only two ACE types
/// have. Everything else used to be SKIPPED — and a skipped entry disappears
/// before the Dart side ever sees the list, so an ACL that grants an ordinary
/// user write through a CONDITIONAL allow (type 9, which Windows resolves at
/// access time) arrived as an ACL that grants nobody anything, and the launch
/// guard passed a path it exists to refuse (report27 V14).
///
/// Skipping is only safe for an entry that cannot GRANT. The Dart side already
/// ignores deny entries on purpose — ignoring a deny can only refuse more
/// often — so a deny this side cannot parse changes nothing. An allow it
/// cannot parse changes everything, and an ACL holding one is not a set of
/// facts; it is an unknown, and the answer is an error.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum AceReading {
    /// `ACCESS_ALLOWED_ACE` / `ACCESS_DENIED_ACE`: header, u32 mask, inline
    /// SID. The only layout this probe reads.
    Plain { allow: bool },
    /// Cannot grant anything: an audit, an alarm, or a deny in a shape this
    /// probe does not parse. Dropping it cannot make the answer more
    /// permissive.
    CannotGrant,
    /// Might grant, in a shape this probe cannot read. The whole answer is
    /// incomplete.
    Unknown,
}

/// Classify one ACE type. Portable on purpose: this is the decision, and it is
/// testable on any host — only the pointer walk around it is Windows-only.
// Compiled everywhere, called only on Windows. The point of splitting the
// DECISION out of the syscall is that it can be tested on any host — the
// project has no Windows CI runner that would otherwise exercise it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn ace_reading(ace_type: u8) -> AceReading {
    match ace_type {
        // ACCESS_ALLOWED_ACE_TYPE / ACCESS_DENIED_ACE_TYPE.
        0 => AceReading::Plain { allow: true },
        1 => AceReading::Plain { allow: false },
        // SYSTEM_AUDIT / SYSTEM_ALARM and their object forms: they record, they
        // do not grant.
        2 | 3 | 7 | 8 => AceReading::CannotGrant,
        // ACCESS_DENIED_OBJECT / _CALLBACK / _CALLBACK_OBJECT, SYSTEM_AUDIT_
        // CALLBACK and friends: denials and audits in layouts this probe does
        // not parse. Ignored exactly as a parsed deny would be.
        6 | 10 | 13 | 15 | 16 => AceReading::CannotGrant,
        // ACCESS_ALLOWED_OBJECT (5), ACCESS_ALLOWED_CALLBACK (9),
        // ACCESS_ALLOWED_CALLBACK_OBJECT (11) — and anything this list does
        // not name. Each of these can grant.
        _ => AceReading::Unknown,
    }
}

/// JSON-escape into a string that is only ever consumed by a JSON parser.
///
/// Windows paths are full of backslashes and an error message can hold
/// anything, so this is not decoration: an unescaped `\` turns a path into an
/// invalid escape and the whole answer becomes unparseable.
fn json_escape(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// `{"error":"..."}` — the shape the Dart side reads as "undetermined".
///
/// Undetermined is never optimistic there: it refuses the launch. So this is
/// the honest answer for every failure, including the ones that look boring.
fn error_json(message: &str) -> String {
    let mut out = String::from("{\"error\":\"");
    json_escape(message, &mut out);
    out.push_str("\"}");
    out
}

#[cfg(windows)]
mod imp {
    use super::{error_json, json_escape};
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo};
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE,
        OWNER_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
    };

    /// `SE_FILE_OBJECT`. Declared here rather than pulled in with another
    /// `windows-sys` feature for a single enum value.
    const SE_FILE_OBJECT: i32 = 1;

    /// An owned handle that closes itself, so no early return leaks it.
    struct Handle(windows_sys::Win32::Foundation::HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: constructed only from a `CreateFileW` success, and this
            // is the only close.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// A security descriptor from `GetSecurityInfo`, freed with `LocalFree`.
    struct Descriptor(*mut core::ffi::c_void);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `GetSecurityInfo` allocates it with `LocalAlloc`.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn wide(path: &str) -> Vec<u16> {
        std::ffi::OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    /// SID as `S-1-5-…`, or `None` when it cannot be rendered.
    ///
    /// # Safety
    /// `sid` must be a valid SID pointer owned by a live descriptor.
    unsafe fn sid_string(sid: *mut core::ffi::c_void) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut raw: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is valid for the descriptor's lifetime; `raw` receives
        // a `LocalAlloc`ed string we free below.
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
            return None;
        }
        // SAFETY: NUL-terminated wide string from the call above.
        let len = unsafe {
            let mut n = 0usize;
            while *raw.add(n) != 0 {
                n += 1;
            }
            n
        };
        // SAFETY: `raw` is valid for `len` u16s.
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
        // SAFETY: allocated by `ConvertSidToStringSidW`.
        unsafe { LocalFree(raw.cast()) };
        Some(text)
    }

    /// Every allow-ACE on the object, as `{sid, rights, allow, inheritOnly}`.
    ///
    /// Deny entries are reported with `allow:false` rather than dropped: the
    /// Dart side decides what to do with them, and it ignores them on purpose
    /// (getting Windows' allow/deny ordering subtly wrong would open the hole
    /// this exists to close, and ignoring can only refuse more often).
    ///
    /// # Safety
    /// `acl` must point at a valid ACL owned by a live descriptor.
    unsafe fn rules_json(acl: *mut ACL) -> Result<String, String> {
        let mut out = String::from("[");
        if acl.is_null() {
            // A NULL DACL grants everyone everything. Saying "no rules" here
            // would read as "nothing is granted" — the exact inversion.
            out.push_str(
                "{\"sid\":\"S-1-1-0\",\"rights\":268435456,\"allow\":true,\"inheritOnly\":false}",
            );
            out.push(']');
            return Ok(out);
        }
        // SAFETY: valid ACL.
        let count = unsafe { (*acl).AceCount } as u32;
        let mut first = true;
        for index in 0..count {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: index < AceCount.
            if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
                // An entry we could not read at all. It may be the one that
                // grants; the list without it is not the ACL (report27 V14).
                return Err(format!("ACL entry {index} could not be read"));
            }
            let header = ace.cast::<ACE_HEADER>();
            // SAFETY: every ACE begins with its header.
            let (ace_type, ace_flags) = unsafe { ((*header).AceType, (*header).AceFlags) };
            // Only the two ACE kinds that carry a plain mask + SID at fixed
            // offsets can be read. One that cannot grant is dropped, exactly
            // as the Dart side drops a parsed deny; one that MIGHT grant makes
            // the whole answer an unknown. See `ace_reading`.
            let allow = match crate::path_acl::ace_reading(ace_type) {
                crate::path_acl::AceReading::Plain { allow } => allow,
                crate::path_acl::AceReading::CannotGrant => continue,
                crate::path_acl::AceReading::Unknown => {
                    return Err(format!(
                        "ACL entry {index} is of type {ace_type}, which this \
                         probe cannot read and which can grant access"
                    ));
                }
            };
            // ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: header, then a u32 mask,
            // then the SID inline.
            // SAFETY: layout fixed by the ACE type checked above.
            let mask = unsafe { *(ace.cast::<u8>().add(4).cast::<u32>()) };
            let sid = unsafe { ace.cast::<u8>().add(8).cast::<core::ffi::c_void>() };
            // SAFETY: the SID lives inside the ACE, which lives in the ACL.
            let Some(sid_text) = (unsafe { sid_string(sid) }) else {
                // An entry we cannot attribute. If it is an allow, dropping it
                // hides a grant.
                return Err(format!("ACL entry {index} has an unreadable SID"));
            };
            let inherit_only = (ace_flags & INHERIT_ONLY_ACE as u8) != 0;
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str("{\"sid\":\"");
            json_escape(&sid_text, &mut out);
            out.push_str(&format!(
                "\",\"rights\":{mask},\"allow\":{allow},\"inheritOnly\":{inherit_only}}}"
            ));
        }
        out.push(']');
        Ok(out)
    }

    /// The whole answer for one path.
    pub(super) fn facts(path: &str) -> String {
        if path.is_empty() {
            return error_json("the path is empty");
        }
        let wide_path = wide(path);
        // SAFETY: NUL-terminated wide path; every out-parameter is owned here.
        let raw = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                // BACKUP_SEMANTICS is what lets a DIRECTORY be opened at all;
                // OPEN_REPARSE_POINT is what stops a junction being followed.
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return error_json(&format!("could not be opened: {}", last_error()));
        }
        let handle = Handle(raw);

        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: live handle, out-parameter owned here.
        if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
            return error_json(&format!("attributes could not be read: {}", last_error()));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            // Deliberately not resolved. Whoever can replace the link decides
            // what the name means, and that is the answer, not a detour.
            return error_json(
                "this path is a reparse point (junction or symbolic link); \
                 permissions read through one describe the target, not who \
                 can repoint it",
            );
        }

        let mut buffer = vec![0u16; 1024];
        // SAFETY: live handle, buffer owned here.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle.0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if len == 0 {
            return error_json(&format!(
                "the final path could not be read: {}",
                last_error()
            ));
        }
        if len as usize >= buffer.len() {
            buffer = vec![0u16; len as usize + 1];
            // SAFETY: as above, with a buffer the call just sized for us.
            let again = unsafe {
                GetFinalPathNameByHandleW(
                    handle.0,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if again == 0 || again as usize >= buffer.len() {
                return error_json("the final path could not be read");
            }
        }
        let final_len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        let final_path = String::from_utf16_lossy(&buffer[..final_len]);

        let mut owner_sid: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; the descriptor is freed by the guard below and
        // owns everything the other out-pointers point into.
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        let _descriptor = Descriptor(descriptor);
        if status != 0 {
            return error_json(&format!(
                "the security descriptor could not be read: {status}"
            ));
        }
        // SAFETY: owned by `_descriptor` until the end of this function.
        let Some(owner) = (unsafe { sid_string(owner_sid) }) else {
            return error_json("the owner could not be read");
        };
        // SAFETY: same.
        let rules = match unsafe { rules_json(dacl) } {
            Ok(rules) => rules,
            // Incomplete facts are not facts. The Dart side reads `error` as
            // undetermined and refuses, which is the answer an ACL this probe
            // cannot fully account for deserves (report27 V14).
            Err(why) => return error_json(&why),
        };

        let mut out = String::from("{\"owner\":\"");
        json_escape(&owner, &mut out);
        out.push_str("\",\"finalPath\":\"");
        json_escape(&final_path, &mut out);
        out.push_str("\",\"rules\":");
        out.push_str(&rules);
        out.push('}');
        out
    }
}

#[cfg(not(windows))]
mod imp {
    use super::error_json;

    pub(super) fn facts(_path: &str) -> String {
        // Not a silent empty answer: the caller reads a missing fact as
        // "undetermined" and refuses, which is what should happen if this is
        // ever reached off Windows.
        error_json("handle-bound permissions are a Windows call")
    }
}

/// Owner and DACL of `path`, read from a handle rather than from the name.
///
/// Writes a NUL-terminated JSON object to `*out_json` — either
/// `{"owner":…,"finalPath":…,"rules":[…]}` or `{"error":…}` — which the caller
/// frees with `veil_free_string`. A path that is a junction or symbolic link
/// is reported as an error rather than resolved: see the module docs.
///
/// Returns [`VEIL_OK`] when `*out_json` was written, [`VEIL_ERR`] otherwise.
///
/// # Safety
/// `path` must point at `path_len` bytes of UTF-8. `out_json` and `err_out`
/// must be valid, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_path_security_facts(
    path: *const u8,
    path_len: usize,
    out_json: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    if out_json.is_null() {
        unsafe { write_err(err_out, "out_json is null".to_string()) };
        return VEIL_ERR;
    }
    if path.is_null() && path_len != 0 {
        unsafe { write_err(err_out, "path is null".to_string()) };
        return VEIL_ERR;
    }
    // SAFETY: caller's contract — `path_len` bytes at `path`.
    let bytes = if path_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(path, path_len) }
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        unsafe { write_err(err_out, "path is not UTF-8".to_string()) };
        return VEIL_ERR;
    };
    let json = imp::facts(text);
    let Ok(c) = std::ffi::CString::new(json) else {
        unsafe { write_err(err_out, "the answer contained a NUL".to_string()) };
        return VEIL_ERR;
    };
    // SAFETY: checked non-null above; ownership passes to the caller.
    unsafe { *out_json = c.into_raw() };
    VEIL_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backslash_survives_the_journey_through_json() {
        // The reason this matters: every Windows path is full of them, and an
        // unescaped one makes the whole answer unparseable rather than wrong
        // in one field.
        let mut out = String::new();
        json_escape(r"C:\Program Files\xVeil", &mut out);
        assert_eq!(out, r"C:\\Program Files\\xVeil");
    }

    #[test]
    fn a_quote_and_a_control_character_cannot_break_out() {
        let mut out = String::new();
        json_escape("say \"hi\"\n\u{7}", &mut out);
        assert_eq!(out, "say \\\"hi\\\"\\n\\u0007");
    }

    /// An ACE this probe cannot read is only droppable if it cannot GRANT.
    ///
    /// Everything but types 0 and 1 used to be skipped, and a skipped entry
    /// disappears before the Dart side sees the list: an ACL granting an
    /// ordinary user write through a CONDITIONAL allow (type 9, resolved by
    /// Windows at access time) arrived as an ACL granting nobody anything, and
    /// the launch guard passed a path it exists to refuse (report27 V14).
    ///
    /// The classification is the decision, and it runs on any host — only the
    /// pointer walk around it is Windows-only.
    #[test]
    fn an_unreadable_ace_that_could_grant_is_not_droppable() {
        use super::{AceReading, ace_reading};

        assert_eq!(ace_reading(0), AceReading::Plain { allow: true });
        assert_eq!(ace_reading(1), AceReading::Plain { allow: false });

        // The ones the report names, and their family: each can GRANT in a
        // layout this probe does not parse.
        for t in [5u8, 9, 11] {
            assert_eq!(
                ace_reading(t),
                AceReading::Unknown,
                "ACE type {t} can grant access and was being dropped silently"
            );
        }
        // And anything not named at all.
        for t in [4u8, 12, 14, 200, 255] {
            assert_eq!(
                ace_reading(t),
                AceReading::Unknown,
                "an unnamed ACE type must be an unknown, not a skip"
            );
        }

        // Audits, alarms and denies this probe cannot parse: dropping one
        // cannot make the answer more permissive, and the Dart side already
        // drops every deny on purpose.
        for t in [2u8, 3, 6, 7, 8, 10, 13, 15, 16] {
            assert_eq!(
                ace_reading(t),
                AceReading::CannotGrant,
                "ACE type {t} cannot grant; refusing on it would fail a normal \
                 installation for nothing"
            );
        }
    }

    #[test]
    fn an_error_is_a_json_object_the_other_side_can_read() {
        let text = error_json("C:\\x said \"no\"");
        assert!(text.starts_with("{\"error\":\""), "{text}");
        assert!(text.ends_with("\"}"), "{text}");
        assert!(text.contains(r"C:\\x"), "the path was not escaped: {text}");
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_it_refuses_rather_than_answering_emptily() {
        let text = imp::facts(r"C:\Windows");
        assert!(text.contains("\"error\""), "{text}");
    }
}
