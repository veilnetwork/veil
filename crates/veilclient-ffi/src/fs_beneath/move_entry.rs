//! A same-directory move with kernel-enforced destination exclusion.
//!
//! A stat followed by an ordinary rename can erase a newly created target.
//! Pin the directory once and let the rename itself refuse an occupied name.
//! This is a publication/recovery primitive, not a complete file transaction:
//! moving a previous version aside and installing a replacement still needs
//! its own recoverable protocol. No C ABI is exposed here yet.

use super::split_components;

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

/// A pinned parent and the two names inside it. Dropping it performs no move.
/// Windows also pins the opened source object; POSIX moves the source entry
/// named at execution time. Neither implementation dereferences a leaf link.
pub(super) struct PreparedMove {
    #[cfg(unix)]
    directory: OwnedFd,
    #[cfg(unix)]
    source: CString,
    #[cfg(unix)]
    destination: CString,
    #[cfg(windows)]
    directory: OwnedHandle,
    #[cfg(windows)]
    source: OwnedHandle,
    #[cfg(windows)]
    destination: String,
}

pub(super) fn destination_leaf(source: &str, destination: &str) -> Result<String, String> {
    let from = split_components(source)?;
    let to = split_components(destination)?;
    // split_components refuses an empty list, so both final indices exist.
    let from_parent = &from[..from.len() - 1];
    let to_parent = &to[..to.len() - 1];
    if from_parent != to_parent {
        return Err("move paths must name the same parent directory".to_owned());
    }
    if from[from.len() - 1] == to[to.len() - 1] {
        return Err("source and destination name the same entry".to_owned());
    }
    #[cfg(windows)]
    if from.iter().chain(to.iter()).any(|part| part.contains(':')) {
        return Err("move paths must not name a drive or alternate data stream".to_owned());
    }
    Ok(to[to.len() - 1].to_owned())
}

impl PreparedMove {
    pub(super) fn open(root: &str, source: &str, destination: &str) -> Result<Self, String> {
        let destination = destination_leaf(source, destination)?;
        #[cfg(unix)]
        {
            let (directory, source) = super::walk_to_parent(root, source)?;
            // SAFETY: walk_to_parent transfers one fresh owned descriptor.
            let directory = unsafe { OwnedFd::from_raw_fd(directory) };
            let destination = CString::new(destination).map_err(|_| "NUL in destination")?;
            Ok(Self {
                directory,
                source,
                destination,
            })
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::DELETE;
            let (directory, leaf) = super::win_walk_to_parent(root, source)?;
            // SAFETY: the walk transfers a fresh owned directory handle.
            let directory = unsafe { OwnedHandle::from_raw_handle(directory) };
            let source = super::win_open_at_with_access(
                directory.as_raw_handle(),
                &leaf,
                false,
                false,
                DELETE,
            )?;
            // SAFETY: the open transfers a fresh owned file handle.
            let source = unsafe { OwnedHandle::from_raw_handle(source) };
            Ok(Self {
                directory,
                source,
                destination,
            })
        }
    }

    /// Prepare another move under a directory already pinned by a transaction.
    /// Reopening the parent by pathname between transaction steps would lose
    /// the containment guarantee even though each individual move was safe.
    pub(super) fn in_parent(
        parent: &std::fs::File,
        source: &str,
        destination: &str,
    ) -> Result<Self, String> {
        let destination = destination_leaf(source, destination)?;
        if split_components(source)?.len() != 1 {
            return Err("move requires sibling leaf names".to_owned());
        }
        let directory = parent.try_clone().map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            Ok(Self {
                directory: directory.into(),
                source: CString::new(source).map_err(|_| "NUL in source")?,
                destination: CString::new(destination).map_err(|_| "NUL in destination")?,
            })
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::DELETE;
            let source = super::win_open_at_with_access(
                directory.as_raw_handle(),
                source,
                false,
                false,
                DELETE,
            )?;
            Ok(Self {
                directory: directory.into(),
                // SAFETY: win_open_at transfers one fresh owned handle.
                source: unsafe { OwnedHandle::from_raw_handle(source) },
                destination,
            })
        }
    }

    /// True after a move; false on an OS-reported name collision. Other errors
    /// are refused without a path-based fallback. A caller must not infer a
    /// complete multi-operation transaction or crash durability from this.
    #[cfg(unix)]
    pub(super) fn execute(self) -> Result<bool, String> {
        let dir = self.directory.as_raw_fd();
        // SAFETY: the directory is held open and both C names outlive the
        // syscall. Atomic exclusion is part of this syscall, not a prior stat.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir,
                self.source.as_ptr(),
                dir,
                self.destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_vendor = "apple")]
        let rc = unsafe {
            libc::renameatx_np(
                dir,
                self.source.as_ptr(),
                dir,
                self.destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if rc == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::EEXIST | libc::ENOTEMPTY)) {
            return Ok(false);
        }
        Err(format!("no-replace move refused: {error}"))
    }

    #[cfg(windows)]
    pub(super) fn execute(self) -> Result<bool, String> {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
        };
        use windows_sys::Win32::Foundation::STATUS_SUCCESS;
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

        // Bound before allocating, and never truncate the length field.
        let units = self.destination.encode_utf16().count();
        let bytes = super::nt_name_byte_len(units).ok_or("destination name is too long")?;
        let name: Vec<u16> = std::ffi::OsStr::new(&self.destination)
            .encode_wide()
            .collect();
        let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let length = offset
            .checked_add(usize::from(bytes))
            .ok_or("rename buffer overflow")?
            // A one-unit name ends before the structure's tail padding. NT
            // still requires the complete header (STATUS_INFO_LENGTH_MISMATCH
            // otherwise); FileNameLength continues to describe only the name.
            .max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
        // usize storage provides pointer alignment, unlike a byte Vec.
        let mut buffer = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: the aligned allocation includes the header and every UTF-16
        // unit. RootDirectory and source handles are owned until after return.
        // The source was opened for synchronous IO plus DELETE access.
        let status = unsafe {
            (*info).Anonymous.ReplaceIfExists = 0;
            (*info).RootDirectory = self.directory.as_raw_handle();
            (*info).FileNameLength = u32::from(bytes);
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            NtSetInformationFile(
                self.source.as_raw_handle(),
                &mut iosb,
                info.cast(),
                u32::try_from(length).map_err(|_| "rename buffer too long")?,
                FileRenameInformation,
            )
        };
        const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
        if status == STATUS_SUCCESS {
            Ok(true)
        } else if status == STATUS_OBJECT_NAME_COLLISION {
            Ok(false)
        } else {
            Err(format!("no-replace move refused (NTSTATUS {status:#x})"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "veil-move-entry-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create private fixture");
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn root(&self) -> &str {
            self.0.to_str().expect("UTF-8 fixture")
        }
        fn put(&self, name: &str, bytes: &[u8]) {
            std::fs::write(self.0.join(name), bytes).unwrap();
        }
        fn read(&self, name: &str) -> Vec<u8> {
            std::fs::read(self.0.join(name)).unwrap()
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove private fixture");
        }
    }

    #[test]
    fn new_name_gets_the_source_bytes() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        assert!(
            PreparedMove::open(tree.root(), "source", "new")
                .unwrap()
                .execute()
                .unwrap()
        );
        assert!(!tree.path().join("source").exists());
        assert_eq!(tree.read("new"), b"incoming");
    }

    #[test]
    fn existing_destination_is_not_replaced() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        tree.put("target", b"local edit");
        assert!(
            !PreparedMove::open(tree.root(), "source", "target")
                .unwrap()
                .execute()
                .unwrap()
        );
        assert_eq!(tree.read("source"), b"incoming");
        assert_eq!(tree.read("target"), b"local edit");
    }

    #[test]
    fn a_destination_created_after_preparation_is_not_replaced() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        let prepared = PreparedMove::open(tree.root(), "source", "target").unwrap();
        tree.put("target", b"late local edit");
        assert!(!prepared.execute().unwrap());
        assert_eq!(tree.read("source"), b"incoming");
        assert_eq!(tree.read("target"), b"late local edit");
    }

    #[test]
    fn dropping_preparation_performs_no_move() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        drop(PreparedMove::open(tree.root(), "source", "target").unwrap());
        assert_eq!(tree.read("source"), b"incoming");
        assert!(!tree.path().join("target").exists());
    }

    #[test]
    fn unicode_and_spaces_are_not_truncated() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        let destination = "файл 漢字 space.txt";
        assert!(
            PreparedMove::open(tree.root(), "source", destination)
                .unwrap()
                .execute()
                .unwrap()
        );
        assert_eq!(tree.read(destination), b"incoming");
    }

    #[test]
    fn short_destination_names_keep_the_complete_native_header() {
        for destination in ["x", "文", "😀"] {
            let tree = Tree::new();
            tree.put("source", b"incoming");
            assert!(
                PreparedMove::open(tree.root(), "source", destination)
                    .unwrap()
                    .execute()
                    .unwrap()
            );
            assert_eq!(tree.read(destination), b"incoming");
        }
    }

    #[test]
    fn an_existing_directory_and_its_contents_are_not_replaced() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        std::fs::create_dir(tree.path().join("target")).unwrap();
        tree.put("target/keep", b"local directory data");
        let result = PreparedMove::open(tree.root(), "source", "target")
            .unwrap()
            .execute();
        assert!(!matches!(result, Ok(true)));
        assert_eq!(tree.read("source"), b"incoming");
        assert_eq!(tree.read("target/keep"), b"local directory data");
    }

    #[test]
    fn unsafe_and_different_parent_paths_are_refused() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        for (from, to) in [
            ("", "x"),
            ("source", ""),
            ("source", "/outside"),
            ("source", "../outside"),
            ("source", "sub/../outside"),
            ("source", "sub/target"),
            ("source", "source"),
            ("source", "x\0y"),
        ] {
            assert!(
                PreparedMove::open(tree.root(), from, to).is_err(),
                "{from:?} -> {to:?}"
            );
            assert_eq!(tree.read("source"), b"incoming");
        }
    }

    #[test]
    fn missing_source_is_a_refusal() {
        let tree = Tree::new();
        let result =
            PreparedMove::open(tree.root(), "absent", "target").and_then(PreparedMove::execute);
        assert!(result.is_err());
        assert!(!tree.path().join("target").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_destination_symlink_is_occupied() {
        use std::os::unix::fs::symlink;
        let tree = Tree::new();
        let outside = Tree::new();
        tree.put("source", b"incoming");
        symlink(outside.path().join("absent"), tree.path().join("target")).unwrap();
        assert!(
            !PreparedMove::open(tree.root(), "source", "target")
                .unwrap()
                .execute()
                .unwrap()
        );
        assert_eq!(tree.read("source"), b"incoming");
        assert!(!outside.path().join("absent").exists());
        assert!(
            tree.path()
                .join("target")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_changed_to_a_symlink_cannot_redirect_a_prepared_move() {
        use std::os::unix::fs::symlink;
        let tree = Tree::new();
        let outside = Tree::new();
        std::fs::create_dir(tree.path().join("parent")).unwrap();
        tree.put("parent/source", b"authorized");
        outside.put("source", b"outside source");
        outside.put("target", b"outside target");
        let prepared = PreparedMove::open(tree.root(), "parent/source", "parent/target").unwrap();
        std::fs::rename(tree.path().join("parent"), tree.path().join("parked")).unwrap();
        symlink(outside.path(), tree.path().join("parent")).unwrap();
        assert!(prepared.execute().unwrap());
        assert_eq!(tree.read("parked/target"), b"authorized");
        assert_eq!(outside.read("source"), b"outside source");
        assert_eq!(outside.read("target"), b"outside target");
        assert!(PreparedMove::open(tree.root(), "parent/source", "parent/new").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn alternate_stream_names_are_refused() {
        let tree = Tree::new();
        tree.put("source", b"incoming");
        for (from, to) in [
            ("source", "target:stream"),
            ("source:stream", "target"),
            ("source", "C:target"),
        ] {
            assert!(PreparedMove::open(tree.root(), from, to).is_err());
        }
        assert_eq!(tree.read("source"), b"incoming");
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_destination_is_not_followed_or_replaced() {
        let tree = Tree::new();
        let outside = Tree::new();
        tree.put("source", b"incoming");
        outside.put("keep", b"outside data");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(tree.path().join("target"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(status.status.success(), "could not create fixture junction");
        let result = PreparedMove::open(tree.root(), "source", "target")
            .unwrap()
            .execute();
        assert!(!matches!(result, Ok(true)));
        assert_eq!(tree.read("source"), b"incoming");
        assert_eq!(outside.read("keep"), b"outside data");
        assert!(
            tree.path()
                .join("target")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_prepared_move_stays_with_the_opened_parent() {
        let tree = Tree::new();
        std::fs::create_dir(tree.path().join("parent")).unwrap();
        tree.put("parent/source", b"authorized");
        let prepared = PreparedMove::open(tree.root(), "parent/source", "parent/target").unwrap();
        let swapped =
            std::fs::rename(tree.path().join("parent"), tree.path().join("parked")).is_ok();
        if swapped {
            std::fs::create_dir(tree.path().join("parent")).unwrap();
            tree.put("parent/source", b"substituted source");
            tree.put("parent/target", b"substituted target");
        }
        assert!(prepared.execute().unwrap());
        if swapped {
            assert_eq!(tree.read("parked/target"), b"authorized");
            assert_eq!(tree.read("parent/source"), b"substituted source");
            assert_eq!(tree.read("parent/target"), b"substituted target");
        } else {
            assert_eq!(tree.read("parent/target"), b"authorized");
        }
    }
}
