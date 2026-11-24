//! Durable acceptance of owner-signed address policy on a Unix node.
//! A single locked file stores the full accepted snapshot and revision.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use crate::network_policy::{
    MAX_SIGNED_ROUTE_POLICY_BYTES, RoutePolicyAuthority, RoutePolicyError, VerifiedRoutePolicy,
    verify_route_policy,
};

const SNAPSHOT_FILE: &str = "route-policy.bin";
const LOCK_FILE: &str = "route-policy.lock";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("route policy state directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("route policy state file is unsafe: {0}")]
    UnsafeFile(PathBuf),
    #[error("route policy state is already initialized")]
    AlreadyInitialized,
    #[error("route policy state is missing; initialize it explicitly on first installation")]
    Uninitialized,
    #[error("route policy revision {offered} is older than accepted revision {accepted}")]
    Rollback { offered: u64, accepted: u64 },
    #[error("route policy revision {0} has conflicting contents")]
    Conflict(u64),
    #[error(transparent)]
    Policy(#[from] RoutePolicyError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct RoutePolicyStore {
    root: PathBuf,
    directory: File,
    owner: u32,
}

impl RoutePolicyStore {
    /// Open an existing directory reserved for one network and service user.
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(StoreError::UnsafeDirectory(root.to_path_buf()));
        }
        let root: PathBuf = root.components().collect();
        // SAFETY: geteuid has no arguments or side effects.
        let owner = unsafe { libc::geteuid() };
        let ancestors: Vec<_> = root.ancestors().collect();
        let mut directory = None;
        for path in ancestors.into_iter().rev() {
            let dir = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| match error.raw_os_error() {
                    Some(libc::ELOOP | libc::ENOTDIR) => {
                        StoreError::UnsafeDirectory(path.to_owned())
                    }
                    _ => StoreError::Io(error),
                })?;
            let meta = dir.metadata()?;
            let sticky = meta.mode() & 0o1000 != 0;
            if (meta.uid() != 0 && meta.uid() != owner)
                || (meta.mode() & 0o022 != 0 && !sticky)
                || (path == root && (meta.uid() != owner || meta.mode() & 0o077 != 0))
                || !safe_acl(&dir)
            {
                return Err(StoreError::UnsafeDirectory(path.to_owned()));
            }
            directory = Some(dir);
        }
        Ok(Self {
            root: root.to_owned(),
            directory: directory.ok_or_else(|| StoreError::UnsafeDirectory(root.to_owned()))?,
            owner,
        })
    }

    /// Read the accepted policy even after expiry. Before using the snapshot
    /// for routes, check its current validity.
    pub fn load(
        &self,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        let _lock = self.lock(false)?;
        let policy = self.load_locked(authority)?;
        self.directory.sync_all()?;
        Ok(policy)
    }

    /// Verify and store a current revision. Initialization requires an empty
    /// store. A later update requires the previous authenticated snapshot.
    pub fn accept(
        &self,
        blob: &[u8],
        authority: &RoutePolicyAuthority<'_>,
        initialize: bool,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        self.accept_with_clock(blob, authority, initialize, veil_util::unix_secs_now_u64)
    }

    fn accept_with_clock(
        &self,
        blob: &[u8],
        authority: &RoutePolicyAuthority<'_>,
        initialize: bool,
        clock: impl FnOnce() -> u64,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        let offered = verify_route_policy(blob, authority)?;
        let _lock = self.lock(initialize)?;
        offered.check_current(clock())?;
        let path = self.root.join(SNAPSHOT_FILE);
        if initialize {
            match fs::symlink_metadata(&path) {
                Ok(_) => return Err(StoreError::AlreadyInitialized),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            let accepted = self.load_locked(authority)?;
            match offered.revision.cmp(&accepted.revision) {
                std::cmp::Ordering::Less => {
                    return Err(StoreError::Rollback {
                        offered: offered.revision,
                        accepted: accepted.revision,
                    });
                }
                std::cmp::Ordering::Equal if offered != accepted => {
                    return Err(StoreError::Conflict(offered.revision));
                }
                std::cmp::Ordering::Equal => {
                    self.directory.sync_all()?;
                    return Ok(accepted);
                }
                std::cmp::Ordering::Greater => {}
            }
        }
        veil_util::atomic_write_owner_only(&path, blob)?;
        // Require the directory barrier as well as the snapshot's file fsync
        // before acknowledging a new accepted revision.
        self.directory.sync_all()?;
        Ok(offered)
    }

    fn lock(&self, initialize: bool) -> Result<File, StoreError> {
        let path = self.root.join(LOCK_FILE);
        let lock = match open_state_file(&path, true, initialize) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Uninitialized);
            }
            result => result?,
        };
        self.require_owner_file(&lock, &path)?;
        lock.lock()?;
        Ok(lock)
    }

    fn load_locked(
        &self,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        let path = self.root.join(SNAPSHOT_FILE);
        let file = match open_state_file(&path, false, false) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Uninitialized);
            }
            result => result?,
        };
        self.require_owner_file(&file, &path)?;
        let mut blob = Vec::new();
        file.take((MAX_SIGNED_ROUTE_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut blob)?;
        Ok(verify_route_policy(&blob, authority)?)
    }

    fn require_owner_file(&self, file: &File, path: &Path) -> Result<(), StoreError> {
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
            || !safe_acl(file)
        {
            return Err(StoreError::UnsafeFile(path.to_owned()));
        }
        Ok(())
    }
}

fn open_state_file(path: &Path, write: bool, create: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(write)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
fn safe_acl(_file: &File) -> bool {
    // POSIX ACL grants are bounded by the group mode bits checked above.
    true
}

#[cfg(target_os = "freebsd")]
fn safe_acl(file: &File) -> bool {
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_NFS4: libc::c_int = 4;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_is_trivial_np(acl: *const libc::c_void, trivial: *mut libc::c_int) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }
    // SAFETY: file owns the descriptor. The ACL handle, when present, is
    // valid until freed by libc; the result points to an initialized int.
    unsafe {
        let fd = file.as_raw_fd();
        match libc::fpathconf(fd, libc::_PC_ACL_NFS4) {
            0 => true, // The group mode bits also bound POSIX.1e ACLs.
            1 => {
                let acl = acl_get_fd_np(fd, ACL_TYPE_NFS4);
                if acl.is_null() {
                    return false;
                }
                let mut trivial = 0;
                let result = acl_is_trivial_np(acl, &mut trivial);
                acl_free(acl);
                result == 0 && trivial == 1
            }
            _ => false,
        }
    }
}

#[cfg(target_os = "macos")]
fn safe_acl(file: &File) -> bool {
    use std::os::fd::AsRawFd as _;
    use std::ptr::null_mut;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_DENY: libc::c_int = 2;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            next: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_valid(acl: *mut libc::c_void) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }
    // SAFETY: the descriptor is owned by file for the call. Each ACL/entry
    // pointer passed back below is obtained from these routines and remains
    // live until acl_free, which we call once for an allocated ACL.
    unsafe {
        let acl = acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            return matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOENT | libc::ENOTSUP)
            );
        }
        let mut allowed = false;
        if acl_valid(acl) == 0 {
            let mut position = ACL_FIRST_ENTRY;
            loop {
                let mut entry = null_mut();
                if acl_get_entry(acl, position, &mut entry) != 0 {
                    // On Darwin EINVAL also signals the end of a valid ACL.
                    allowed = io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL);
                    break;
                }
                let mut tag = 0;
                if acl_get_tag_type(entry, &mut tag) != 0 || tag != ACL_EXTENDED_DENY {
                    break;
                }
                position = ACL_NEXT_ENTRY;
            }
        }
        acl_free(acl);
        allowed
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use veil_crypto::signature::GeneratedKeyPair;
    use veil_types::SignatureAlgorithm;

    use super::*;
    use crate::network_policy::{RoutePolicy, RoutePolicyMember, sign_route_policy};

    const NETWORK: [u8; 32] = [9; 32];
    const ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::Ed25519;

    fn signed(key: &GeneratedKeyPair, revision: u64, expiry: u64, host: u8) -> Vec<u8> {
        let policy = RoutePolicy {
            network_id: NETWORK,
            revision,
            valid_from_unix: 10,
            valid_until_unix: expiry,
            ipv4_range: Some("198.18.0.0/24".parse().unwrap()),
            ipv6_range: None,
            members: vec![RoutePolicyMember {
                node_id: [11; 32],
                addr_v4: Some(std::net::Ipv4Addr::new(198, 18, 0, host)),
                addr_v6: None,
            }],
        };
        sign_route_policy(policy, ALGORITHM, &key.public_key, &key.private_key).unwrap()
    }

    fn directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn accepted_revision_survives_restart_and_expiration() {
        let dir = directory();
        let path = dir.path().canonicalize().unwrap();
        let key = veil_crypto::generate_keypair(ALGORITHM);
        let authority = RoutePolicyAuthority {
            network_id: NETWORK,
            algorithm: ALGORITHM,
            public_key: &key.public_key,
        };
        let next = signed(&key, 9, 100, 2);
        let store = RoutePolicyStore::open(&path).unwrap();
        assert!(matches!(
            store.accept_with_clock(&next, &authority, false, || 50),
            Err(StoreError::Uninitialized)
        ));
        store
            .accept_with_clock(&next, &authority, true, || 50)
            .unwrap();
        drop(store);

        let store = RoutePolicyStore::open(&path).unwrap();
        let accepted = store.load(&authority).unwrap();
        assert_eq!(accepted.revision, 9);
        assert!(accepted.check_current(101).is_err());
        let replay = signed(&key, 8, 200, 3);
        assert!(matches!(
            store.accept_with_clock(&replay, &authority, false, || 101),
            Err(StoreError::Rollback {
                offered: 8,
                accepted: 9
            })
        ));
        let conflict = signed(&key, 9, 200, 4);
        assert!(matches!(
            store.accept_with_clock(&conflict, &authority, false, || 101),
            Err(StoreError::Conflict(9))
        ));
        assert!(matches!(
            store.accept_with_clock(&replay, &authority, true, || 101),
            Err(StoreError::AlreadyInitialized)
        ));
        assert_eq!(store.load(&authority).unwrap(), accepted);

        let latest = signed(&key, 10, 200, 5);
        store
            .accept_with_clock(&latest, &authority, false, || 101)
            .unwrap();
        store
            .accept_with_clock(&latest, &authority, false, || 102)
            .unwrap();
        assert_eq!(store.load(&authority).unwrap().revision, 10);
    }

    #[test]
    fn concurrent_installations_keep_the_newest_revision() {
        let dir = directory();
        let path = dir.path().canonicalize().unwrap();
        let key = veil_crypto::generate_keypair(ALGORITHM);
        let authority = RoutePolicyAuthority {
            network_id: NETWORK,
            algorithm: ALGORITHM,
            public_key: &key.public_key,
        };
        let store = RoutePolicyStore::open(&path).unwrap();
        store
            .accept_with_clock(&signed(&key, 1, 500, 2), &authority, true, || 50)
            .unwrap();
        let older = signed(&key, 2, 500, 3);
        let newer = signed(&key, 3, 500, 4);
        std::thread::scope(|scope| {
            let second = scope.spawn(|| {
                RoutePolicyStore::open(&path).unwrap().accept_with_clock(
                    &older,
                    &authority,
                    false,
                    || 60,
                )
            });
            let third = scope.spawn(|| {
                RoutePolicyStore::open(&path).unwrap().accept_with_clock(
                    &newer,
                    &authority,
                    false,
                    || 60,
                )
            });
            third.join().unwrap().unwrap();
            if let Err(error) = second.join().unwrap() {
                assert!(matches!(error, StoreError::Rollback { accepted: 3, .. }));
            }
        });
        assert_eq!(store.load(&authority).unwrap().revision, 3);
    }

    #[test]
    fn replaced_or_unsafe_state_is_refused() {
        let dir = directory();
        let path = dir.path().canonicalize().unwrap();
        let alias = path.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(matches!(
            RoutePolicyStore::open(&alias),
            Err(StoreError::UnsafeDirectory(_))
        ));
        let unsafe_path = path.join("insecure");
        fs::create_dir(&unsafe_path).unwrap();
        fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            RoutePolicyStore::open(&unsafe_path),
            Err(StoreError::UnsafeDirectory(_))
        ));

        let key = veil_crypto::generate_keypair(ALGORITHM);
        let authority = RoutePolicyAuthority {
            network_id: NETWORK,
            algorithm: ALGORITHM,
            public_key: &key.public_key,
        };
        let store = RoutePolicyStore::open(&path).unwrap();
        store
            .accept_with_clock(&signed(&key, 1, 500, 2), &authority, true, || 50)
            .unwrap();
        let snapshot = path.join(SNAPSHOT_FILE);
        fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            store.load(&authority),
            Err(StoreError::UnsafeFile(_))
        ));
        fs::remove_file(&snapshot).unwrap();
        assert!(matches!(
            store.accept_with_clock(&signed(&key, 2, 500, 3), &authority, false, || 60),
            Err(StoreError::Uninitialized)
        ));
    }
}
