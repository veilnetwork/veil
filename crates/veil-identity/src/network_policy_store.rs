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
use crate::network_recovery::{
    OwnerRecovery, OwnerRecoveryError, owner_key_id, verify_owner_recovery,
};

const SNAPSHOT_FILE: &str = "route-policy.bin";
const LOCK_FILE: &str = "route-policy.lock";
const ENROLLED_MAGIC: &[u8] = b"veil/p-net/recovery-state/v1\0";
const MAX_RETIRED_OWNERS: usize = u16::MAX as usize;
const RECOVERY_HEADER_BYTES: usize = ENROLLED_MAGIC.len() + 32 + 2;
const MAX_STORED_POLICY_BYTES: usize =
    MAX_SIGNED_ROUTE_POLICY_BYTES + RECOVERY_HEADER_BYTES + MAX_RETIRED_OWNERS * 32;

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
    #[error("route policy state is busy")]
    Busy,
    #[error("route policy revision {offered} is older than accepted revision {accepted}")]
    Rollback { offered: u64, accepted: u64 },
    #[error("route policy revision {0} has conflicting contents")]
    Conflict(u64),
    #[error("owner rotation requires a different owner key")]
    SameOwner,
    #[error("owner rotation requires a revision newer than {accepted}, offered {offered}")]
    RotationRevision { offered: u64, accepted: u64 },
    #[error("stored policy did not verify against the current owner: {0}")]
    RotationCurrent(#[source] RoutePolicyError),
    #[error("replacement policy did not verify against the successor: {0}")]
    RotationSuccessor(#[source] RoutePolicyError),
    #[error("a different recovery key is already pinned for this policy store")]
    RecoveryAlreadyPinned,
    #[error("no recovery key is pinned for this policy store")]
    RecoveryNotPinned,
    #[error("the supplied recovery key does not match the pinned key")]
    RecoveryKeyMismatch,
    #[error("the recovery key cannot become the network owner")]
    RecoveryKeyAsOwner,
    #[error("a retired owner key cannot be used again")]
    RetiredOwner,
    #[error("route policy state has an invalid recovery header")]
    InvalidRecoveryState,
    #[error("route policy state has reached its retired-owner limit")]
    TooManyRetiredOwners,
    #[error(transparent)]
    Recovery(#[from] OwnerRecoveryError),
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

struct StoredPolicy {
    signed: Vec<u8>,
    recovery: Option<RecoveryState>,
}

struct RecoveryState {
    key: [u8; 32],
    retired: Vec<[u8; 32]>,
}

impl StoredPolicy {
    fn decode(mut bytes: Vec<u8>) -> Result<Self, StoreError> {
        let mut recovery = None;
        if let Some(header) = bytes.strip_prefix(ENROLLED_MAGIC) {
            let (key, header) = header
                .split_first_chunk::<32>()
                .ok_or(StoreError::InvalidRecoveryState)?;
            let (count, tail) = header
                .split_first_chunk::<2>()
                .ok_or(StoreError::InvalidRecoveryState)?;
            let history_bytes = usize::from(u16::from_be_bytes(*count)) * 32;
            let history = tail
                .get(..history_bytes)
                .ok_or(StoreError::InvalidRecoveryState)?;
            recovery = Some(RecoveryState {
                key: *key,
                retired: history.as_chunks::<32>().0.to_vec(),
            });
            bytes.drain(..RECOVERY_HEADER_BYTES + history_bytes);
        }
        if bytes.len() > MAX_SIGNED_ROUTE_POLICY_BYTES {
            return Err(RoutePolicyError::Format.into());
        }
        Ok(Self {
            signed: bytes,
            recovery,
        })
    }
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
        let directory = open_trusted_directory(&root, owner, true)?;
        Ok(Self {
            root,
            directory,
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
        self.load_synced(authority).map(|(policy, _)| policy)
    }

    /// Load for a running service without waiting on another local installer.
    pub fn try_load(
        &self,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        self.try_load_signed(authority).map(|(policy, _)| policy)
    }

    /// Read the verified snapshot and its original signed bytes.
    pub fn try_load_signed(
        &self,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<(VerifiedRoutePolicy, Vec<u8>), StoreError> {
        let _lock = self.try_lock()?;
        self.load_synced(authority)
    }

    fn load_synced(
        &self,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<(VerifiedRoutePolicy, Vec<u8>), StoreError> {
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

    /// Accept an update in an initialized store without waiting for its lock.
    pub fn try_accept(
        &self,
        blob: &[u8],
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        let offered = verify_route_policy(blob, authority)?;
        let _lock = self.try_lock()?;
        self.accept_locked(
            blob,
            authority,
            offered,
            false,
            veil_util::unix_secs_now_u64(),
        )
    }

    /// Replace the policy using a separately authenticated successor pin.
    /// Only a local operator can select a successor. Network updates still
    /// require the same owner on both the offered and persisted snapshots.
    pub fn replace_owner(
        &self,
        blob: &[u8],
        current: &RoutePolicyAuthority<'_>,
        successor: &RoutePolicyAuthority<'_>,
        check_only: bool,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        self.replace_owner_with_clock(
            blob,
            current,
            successor,
            check_only,
            veil_util::unix_secs_now_u64,
        )
    }

    /// Enroll a separate public key before an emergency. This operation
    /// preserves the current signed policy and cannot replace an existing pin.
    pub fn pin_recovery(
        &self,
        current: &RoutePolicyAuthority<'_>,
        recovery: &RoutePolicyAuthority<'_>,
    ) -> Result<(), StoreError> {
        if current.network_id != recovery.network_id {
            return Err(OwnerRecoveryError::WrongNetwork.into());
        }
        let key = owner_key_id(recovery)?;
        if key == owner_key_id(current)? {
            return Err(OwnerRecoveryError::RepeatedKey.into());
        }
        let _lock = self.lock(false)?;
        let stored = self.read_locked()?;
        verify_route_policy(&stored.signed, current)?;
        if let Some(existing) = stored.recovery {
            if key != existing.key {
                return Err(StoreError::RecoveryAlreadyPinned);
            }
            self.directory.sync_all()?;
            return Ok(());
        }
        self.persist_locked(
            &stored.signed,
            Some(&RecoveryState {
                key,
                retired: Vec::new(),
            }),
        )
    }

    /// Recover into a fresh owner using an exact snapshot authorized by the
    /// enrolled key. The replacement starts its own policy revision history.
    pub fn recover_owner(
        &self,
        blob: &[u8],
        current: &RoutePolicyAuthority<'_>,
        successor: &RoutePolicyAuthority<'_>,
        recovery: &OwnerRecovery<'_>,
        check_only: bool,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        self.change_owner(
            blob,
            current,
            successor,
            check_only,
            Some(recovery),
            veil_util::unix_secs_now_u64,
        )
    }

    fn replace_owner_with_clock(
        &self,
        blob: &[u8],
        current: &RoutePolicyAuthority<'_>,
        successor: &RoutePolicyAuthority<'_>,
        check_only: bool,
        clock: impl FnOnce() -> u64,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        self.change_owner(blob, current, successor, check_only, None, clock)
    }

    fn change_owner(
        &self,
        blob: &[u8],
        current: &RoutePolicyAuthority<'_>,
        successor: &RoutePolicyAuthority<'_>,
        check_only: bool,
        recovery: Option<&OwnerRecovery<'_>>,
        clock: impl FnOnce() -> u64,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        if current.network_id != successor.network_id {
            return Err(RoutePolicyError::WrongNetwork.into());
        }
        if current.algorithm == successor.algorithm && current.public_key == successor.public_key {
            return Err(StoreError::SameOwner);
        }
        let offered =
            verify_route_policy(blob, successor).map_err(StoreError::RotationSuccessor)?;
        let _lock = self.lock(false)?;
        offered.check_current(clock())?;
        let mut stored = self.read_locked()?;
        let current_key = Self::check_owner_change(&stored, blob, current, successor, recovery)?;
        if stored.signed == blob
            && stored
                .recovery
                .as_ref()
                .is_none_or(|state| state.retired.last() == current_key.as_ref())
        {
            // An identical, currently valid successor snapshot means the
            // replacement was already applied. Repeat the durability barrier
            // in case the prior caller was interrupted after the rename.
            if !check_only {
                self.directory.sync_all()?;
            }
            return Ok(offered);
        }
        let accepted =
            verify_route_policy(&stored.signed, current).map_err(StoreError::RotationCurrent)?;
        if recovery.is_none() && offered.revision <= accepted.revision {
            return Err(StoreError::RotationRevision {
                offered: offered.revision,
                accepted: accepted.revision,
            });
        }
        if let Some((state, retired_key)) = stored.recovery.as_mut().zip(current_key) {
            if state.retired.len() == MAX_RETIRED_OWNERS {
                return Err(StoreError::TooManyRetiredOwners);
            }
            state.retired.push(retired_key);
        }
        if !check_only {
            self.persist_locked(blob, stored.recovery.as_ref())?;
        }
        Ok(offered)
    }

    fn check_owner_change(
        stored: &StoredPolicy,
        blob: &[u8],
        current: &RoutePolicyAuthority<'_>,
        successor: &RoutePolicyAuthority<'_>,
        recovery: Option<&OwnerRecovery<'_>>,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let Some(state) = &stored.recovery else {
            return if recovery.is_some() {
                Err(StoreError::RecoveryNotPinned)
            } else {
                Ok(None)
            };
        };
        let next_key = owner_key_id(successor)?;
        if next_key == state.key {
            return Err(StoreError::RecoveryKeyAsOwner);
        }
        if state.retired.contains(&next_key) {
            return Err(StoreError::RetiredOwner);
        }
        if let Some(recovery) = recovery {
            if owner_key_id(recovery.authority)? != state.key {
                return Err(StoreError::RecoveryKeyMismatch);
            }
            verify_owner_recovery(blob, current, successor, recovery)?;
        }
        Ok(Some(owner_key_id(current)?))
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
        self.accept_locked(blob, authority, offered, initialize, clock())
    }

    fn accept_locked(
        &self,
        blob: &[u8],
        authority: &RoutePolicyAuthority<'_>,
        offered: VerifiedRoutePolicy,
        initialize: bool,
        now: u64,
    ) -> Result<VerifiedRoutePolicy, StoreError> {
        offered.check_current(now)?;
        let recovery = if initialize {
            let path = self.root.join(SNAPSHOT_FILE);
            match fs::symlink_metadata(&path) {
                Ok(_) => return Err(StoreError::AlreadyInitialized),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            None
        } else {
            let stored = self.read_locked()?;
            let accepted = verify_route_policy(&stored.signed, authority)?;
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
            stored.recovery
        };
        self.persist_locked(blob, recovery.as_ref())?;
        Ok(offered)
    }

    fn persist_locked(
        &self,
        blob: &[u8],
        recovery: Option<&RecoveryState>,
    ) -> Result<(), StoreError> {
        let wrapped;
        let bytes = if let Some(state) = recovery {
            let count =
                u16::try_from(state.retired.len()).map_err(|_| StoreError::TooManyRetiredOwners)?;
            wrapped = [
                ENROLLED_MAGIC,
                state.key.as_slice(),
                &count.to_be_bytes(),
                state.retired.as_flattened(),
                blob,
            ]
            .concat();
            wrapped.as_slice()
        } else {
            blob
        };
        veil_util::atomic_write_owner_only(&self.root.join(SNAPSHOT_FILE), bytes)?;
        // Require the directory barrier as well as the snapshot's file fsync
        // before acknowledging a new accepted revision.
        self.directory.sync_all()?;
        Ok(())
    }

    fn lock(&self, initialize: bool) -> Result<File, StoreError> {
        let lock = self.open_lock(initialize)?;
        lock.lock()?;
        Ok(lock)
    }

    fn try_lock(&self) -> Result<File, StoreError> {
        let lock = self.open_lock(false)?;
        match lock.try_lock() {
            Ok(()) => Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) => Err(StoreError::Busy),
            Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
        }
    }

    fn open_lock(&self, initialize: bool) -> Result<File, StoreError> {
        let path = self.root.join(LOCK_FILE);
        let lock = match open_state_file(&path, true, initialize) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Uninitialized);
            }
            result => result?,
        };
        self.require_owner_file(&lock, &path)?;
        Ok(lock)
    }

    fn load_locked(
        &self,
        authority: &RoutePolicyAuthority<'_>,
    ) -> Result<(VerifiedRoutePolicy, Vec<u8>), StoreError> {
        let stored = self.read_locked()?;
        Ok((
            verify_route_policy(&stored.signed, authority)?,
            stored.signed,
        ))
    }

    fn read_locked(&self) -> Result<StoredPolicy, StoreError> {
        let path = self.root.join(SNAPSHOT_FILE);
        let file = match open_state_file(&path, false, false) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Uninitialized);
            }
            result => result?,
        };
        self.require_owner_file(&file, &path)?;
        let mut blob = Vec::new();
        file.take((MAX_STORED_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut blob)?;
        StoredPolicy::decode(blob)
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

// Signed route configuration supplies the pinned owner. Check the bytes
// that were parsed through a protected path before trusting that pin.
pub fn verify_policy_configuration(path: &Path, parsed: &[u8]) -> Result<(), StoreError> {
    let absolute = std::path::absolute(path)?;
    if absolute
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(StoreError::UnsafeFile(absolute));
    }
    let path: PathBuf = absolute.components().collect();
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::UnsafeFile(path.clone()))?;
    // SAFETY: geteuid has no arguments or side effects.
    let owner = unsafe { libc::geteuid() };
    let _directory = open_trusted_directory(parent, owner, false)?;
    let file = open_state_file(&path, false, false)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || (meta.uid() != owner && meta.uid() != 0)
        || meta.mode() & 0o022 != 0
        || !safe_acl(&file)
    {
        return Err(StoreError::UnsafeFile(path));
    }
    let mut actual = Vec::new();
    file.take(parsed.len() as u64 + 1)
        .read_to_end(&mut actual)?;
    if actual != parsed {
        return Err(
            io::Error::other("signed policy configuration changed while opening it").into(),
        );
    }
    Ok(())
}

fn open_trusted_directory(root: &Path, owner: u32, private_leaf: bool) -> Result<File, StoreError> {
    let ancestors: Vec<_> = root.ancestors().collect();
    let mut directory = None;
    for path in ancestors.into_iter().rev() {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| match error.raw_os_error() {
                Some(libc::ELOOP | libc::ENOTDIR) => StoreError::UnsafeDirectory(path.to_owned()),
                _ => StoreError::Io(error),
            })?;
        let meta = dir.metadata()?;
        let sticky = meta.mode() & 0o1000 != 0;
        if (meta.uid() != 0 && meta.uid() != owner)
            || (meta.mode() & 0o022 != 0 && !sticky)
            || (private_leaf && path == root && (meta.uid() != owner || meta.mode() & 0o077 != 0))
            || !safe_acl(&dir)
        {
            return Err(StoreError::UnsafeDirectory(path.to_owned()));
        }
        directory = Some(dir);
    }
    directory.ok_or_else(|| StoreError::UnsafeDirectory(root.to_owned()))
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
    fn automatic_updates_require_an_initialized_and_unlocked_store() {
        let dir = directory();
        let path = dir.path().canonicalize().unwrap();
        let key = veil_crypto::generate_keypair(ALGORITHM);
        let authority = RoutePolicyAuthority {
            network_id: NETWORK,
            algorithm: ALGORITHM,
            public_key: &key.public_key,
        };
        let expiry = veil_util::unix_secs_now_u64() + 600;
        let policy = signed(&key, 1, expiry, 2);
        let store = RoutePolicyStore::open(&path).unwrap();
        assert!(matches!(
            store.try_accept(&policy, &authority),
            Err(StoreError::Uninitialized)
        ));
        store.accept(&policy, &authority, true).unwrap();
        let next = signed(&key, 2, expiry, 3);
        let lock = store.lock(false).unwrap();
        assert!(matches!(
            store.try_accept(&next, &authority),
            Err(StoreError::Busy)
        ));
        assert!(matches!(
            store.try_load_signed(&authority),
            Err(StoreError::Busy)
        ));
        drop(lock);
        assert_eq!(store.try_accept(&next, &authority).unwrap().revision, 2);
        let (accepted, bytes) = store.try_load_signed(&authority).unwrap();
        assert_eq!(accepted.revision, 2);
        assert_eq!(bytes, next);
    }

    #[test]
    fn owner_rotation_preserves_the_revision_floor_and_requires_explicit_pins() {
        let dir = directory();
        let path = dir.path().canonicalize().unwrap();
        let old_key = veil_crypto::generate_keypair(ALGORITHM);
        let new_key = veil_crypto::generate_keypair(ALGORITHM);
        let other_key = veil_crypto::generate_keypair(ALGORITHM);
        let previous = RoutePolicyAuthority {
            network_id: NETWORK,
            algorithm: ALGORITHM,
            public_key: &old_key.public_key,
        };
        let successor = RoutePolicyAuthority {
            public_key: &new_key.public_key,
            ..previous
        };
        let other = RoutePolicyAuthority {
            public_key: &other_key.public_key,
            ..previous
        };
        let store = RoutePolicyStore::open(&path).unwrap();
        let original = signed(&old_key, 8, 100, 2);
        let replacement = signed(&new_key, 9, 200, 3);
        assert!(matches!(
            store.replace_owner_with_clock(&replacement, &previous, &successor, false, || 50),
            Err(StoreError::Uninitialized)
        ));
        store
            .accept_with_clock(&original, &previous, true, || 50)
            .unwrap();

        let stale = signed(&new_key, 8, 200, 3);
        assert!(matches!(
            store.replace_owner_with_clock(&stale, &previous, &successor, false, || 110),
            Err(StoreError::RotationRevision {
                offered: 8,
                accepted: 8
            })
        ));
        assert!(matches!(
            store.replace_owner_with_clock(&replacement, &previous, &successor, false, || 200),
            Err(StoreError::Policy(RoutePolicyError::Expired(200)))
        ));
        assert!(matches!(
            store.replace_owner_with_clock(&replacement, &successor, &successor, false, || 110),
            Err(StoreError::SameOwner)
        ));
        assert!(matches!(
            store.replace_owner_with_clock(&replacement, &previous, &other, false, || 110),
            Err(StoreError::RotationSuccessor(RoutePolicyError::Signature(
                _
            )))
        ));
        assert!(matches!(
            store.replace_owner_with_clock(&replacement, &other, &successor, false, || 110),
            Err(StoreError::RotationCurrent(RoutePolicyError::Signature(_)))
        ));
        assert_eq!(
            store
                .replace_owner_with_clock(&replacement, &previous, &successor, true, || 110)
                .unwrap()
                .revision,
            9
        );
        assert_eq!(store.try_load_signed(&previous).unwrap().1, original);
        assert!(store.load(&successor).is_err());

        store
            .replace_owner_with_clock(&replacement, &previous, &successor, false, || 110)
            .unwrap();
        drop(store);
        let store = RoutePolicyStore::open(&path).unwrap();
        assert_eq!(store.try_load_signed(&successor).unwrap().1, replacement);
        assert!(store.load(&previous).is_err());
        store
            .replace_owner_with_clock(&replacement, &previous, &successor, false, || 120)
            .unwrap();
        let old_update = signed(&old_key, 100, 300, 4);
        assert!(matches!(
            store.accept_with_clock(&old_update, &previous, false, || 120),
            Err(StoreError::Policy(RoutePolicyError::Signature(_)))
        ));
        assert!(matches!(
            store.accept_with_clock(&stale, &successor, false, || 120),
            Err(StoreError::Rollback {
                offered: 8,
                accepted: 9
            })
        ));
        let update = signed(&new_key, 10, 300, 4);
        store
            .accept_with_clock(&update, &successor, false, || 120)
            .unwrap();
        assert_eq!(store.try_load_signed(&successor).unwrap().1, update);
    }

    #[test]
    fn enrolled_recovery_survives_maximum_revision_and_retires_the_previous_key() {
        use crate::network_recovery::sign_owner_recovery;

        let dir = directory();
        let path = dir.path().canonicalize().unwrap();
        let old_key = veil_crypto::generate_keypair(ALGORITHM);
        let new_key = veil_crypto::generate_keypair(ALGORITHM);
        let recovery_key = veil_crypto::generate_keypair(ALGORITHM);
        let other_key = veil_crypto::generate_keypair(ALGORITHM);
        let pins =
            [&old_key, &new_key, &recovery_key, &other_key].map(|key| RoutePolicyAuthority {
                network_id: NETWORK,
                algorithm: ALGORITHM,
                public_key: &key.public_key,
            });
        let [old, next, recovery, other] = &pins;
        let replacement = signed(&new_key, 1, 500, 3);
        let old_snapshot = signed(&old_key, u64::MAX, 400, 2);
        let proof =
            sign_owner_recovery(&replacement, old, next, recovery, &recovery_key.private_key)
                .unwrap();
        let auth = OwnerRecovery {
            authority: recovery,
            signature: &proof,
        };
        let store = RoutePolicyStore::open(&path).unwrap();
        store
            .accept_with_clock(&old_snapshot, old, true, || 50)
            .unwrap();
        assert!(matches!(
            store.change_owner(&replacement, old, next, false, Some(&auth), || 60),
            Err(StoreError::RecoveryNotPinned)
        ));
        assert!(store.pin_recovery(old, old).is_err());
        let weak = RoutePolicyAuthority {
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ..*recovery
        };
        assert!(matches!(
            store.pin_recovery(old, &weak),
            Err(StoreError::Recovery(OwnerRecoveryError::WeakEd25519Key))
        ));
        store.pin_recovery(old, recovery).unwrap();
        store.pin_recovery(old, recovery).unwrap();
        assert!(matches!(
            store.pin_recovery(old, other),
            Err(StoreError::RecoveryAlreadyPinned)
        ));
        assert!(matches!(
            store.replace_owner_with_clock(&replacement, old, next, false, || 60),
            Err(StoreError::RotationRevision {
                offered: 1,
                accepted: u64::MAX,
            })
        ));
        let mismatched_pin = OwnerRecovery {
            authority: other,
            signature: &proof,
        };
        assert!(matches!(
            store.change_owner(&replacement, old, next, false, Some(&mismatched_pin), || 60),
            Err(StoreError::RecoveryKeyMismatch)
        ));
        let other_policy = signed(&new_key, 2, 500, 4);
        assert!(matches!(
            store.change_owner(&other_policy, old, next, false, Some(&auth), || 60),
            Err(StoreError::Recovery(OwnerRecoveryError::Signature(_)))
        ));
        store
            .change_owner(&replacement, old, next, true, Some(&auth), || 60)
            .unwrap();
        assert_eq!(store.try_load_signed(old).unwrap().1, old_snapshot);
        store
            .change_owner(&replacement, old, next, false, Some(&auth), || 450)
            .unwrap();
        drop(store);
        let store = RoutePolicyStore::open(&path).unwrap();
        store
            .change_owner(&replacement, old, next, false, Some(&auth), || 451)
            .unwrap();
        assert_eq!(store.try_load_signed(next).unwrap().1, replacement);
        assert!(store.load(old).is_err());

        store
            .accept_with_clock(&other_policy, next, false, || 451)
            .unwrap();
        assert!(matches!(
            store.change_owner(&replacement, old, next, false, Some(&auth), || 452),
            Err(StoreError::RotationCurrent(RoutePolicyError::Signature(_)))
        ));
        let retired_offer = signed(&old_key, 3, 600, 4);
        assert!(matches!(
            store.replace_owner_with_clock(&retired_offer, next, old, false, || 452),
            Err(StoreError::RetiredOwner)
        ));
        let recovery_offer = signed(&recovery_key, 3, 600, 4);
        assert!(matches!(
            store.replace_owner_with_clock(&recovery_offer, next, recovery, false, || 452),
            Err(StoreError::RecoveryKeyAsOwner)
        ));
        assert_eq!(store.try_load_signed(next).unwrap().1, other_policy);
        let later = signed(&other_key, 3, 600, 4);
        store
            .replace_owner_with_clock(&later, next, other, false, || 452)
            .unwrap();
        assert!(matches!(
            store.replace_owner_with_clock(&other_policy, other, next, false, || 453),
            Err(StoreError::RetiredOwner)
        ));
        assert_eq!(store.try_load_signed(other).unwrap().1, later);
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
