//! Durable federation state.
//!
//! Four things must survive a restart, and each for a different reason.
//!
//! * The **identity seed**, because a peer that regenerates its key on every start looks
//!   like a new peer each time, and its earlier evidence can no longer be attributed to it.
//! * The **paired peers**, because pairing is a deliberate human act and re-doing it on
//!   every restart is the same as not having it.
//! * The **outbound sequence**, because reusing a number a peer has already accepted makes
//!   this peer's own bundles look like replays and they are silently dropped.
//! * The **inbound cursor**, because replay protection that forgets on restart protects
//!   nothing: a captured bundle replayed after a restart would be accepted.
//!
//! Written atomically through a temporary file and a rename, so an interrupted write leaves
//! the previous state rather than a half-file. The seed is a secret, so the file is created
//! 0600 and the directory 0700 before anything is written into them.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::identity::{PeerId, PeerKey, decode_hex, encode_hex};

/// The on-disk form. Field names are part of the file format.
///
/// `Debug` is written by hand so the seed cannot reach a log through a derived one.
#[derive(Clone, Serialize, Deserialize, Default)]
struct StoredState {
    /// Ed25519 seed, hex. Secret.
    identity_seed: String,
    /// Paired peers, hex public key to the note recorded when pairing.
    #[serde(default)]
    paired: BTreeMap<String, String>,
    /// Highest sequence this peer has published.
    #[serde(default)]
    outbound_sequence: u64,
    /// Highest sequence accepted from each peer.
    #[serde(default)]
    inbound_cursor: BTreeMap<String, u64>,
}

impl std::fmt::Debug for StoredState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredState")
            .field("identity_seed", &"<redacted>")
            .field("paired", &self.paired.len())
            .field("outbound_sequence", &self.outbound_sequence)
            .field("inbound_cursor", &self.inbound_cursor.len())
            .finish()
    }
}

/// Federation state, loaded from disk and written back atomically.
///
/// `Debug` prints the path and identity only. The seed lives in [`PeerKey`], whose own
/// `Debug` never reveals it.
#[derive(Debug)]
pub struct FederationStore {
    path: PathBuf,
    key: PeerKey,
    state: StoredState,
}

impl FederationStore {
    /// Loads state from `path`, creating a fresh identity if there is none.
    ///
    /// A file that cannot be parsed is an error rather than a reason to start over: silently
    /// generating a new identity would discard every pairing the operator made and change
    /// who this machine claims to be.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            restrict_directory(parent)?;
        }

        let state = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<StoredState>(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => StoredState::default(),
            Err(e) => return Err(e),
        };

        let (key, state) = if state.identity_seed.is_empty() {
            let key = PeerKey::generate();
            let state = StoredState {
                identity_seed: encode_hex(&key.seed()),
                ..state
            };
            (key, state)
        } else {
            let seed = decode_hex(&state.identity_seed).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "identity seed is not hex")
            })?;
            let key = PeerKey::from_seed(&seed).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("identity seed: {e}"))
            })?;
            (key, state)
        };

        let mut store = Self { path, key, state };
        store.persist()?;
        Ok(store)
    }

    pub fn identity(&self) -> &PeerKey {
        &self.key
    }

    pub fn peer_id(&self) -> PeerId {
        self.key.id()
    }

    /// Records a pairing, with the operator's note about who this peer is.
    ///
    /// The in-memory change is rolled back if it cannot be written. Otherwise a full disk
    /// leaves this process believing a peer is paired while the next start disagrees, and
    /// the two views diverge silently.
    pub fn pair(&mut self, peer: &PeerId, note: &str) -> io::Result<()> {
        self.commit(|state| {
            state.paired.insert(peer.to_hex(), note.to_string());
        })
    }

    pub fn unpair(&mut self, peer: &PeerId) -> io::Result<()> {
        self.commit(|state| {
            state.paired.remove(&peer.to_hex());
        })
    }

    /// Applies a change and writes it, restoring the previous state if the write fails.
    fn commit<F: FnOnce(&mut StoredState)>(&mut self, change: F) -> io::Result<()> {
        let previous = self.state.clone();
        change(&mut self.state);
        if let Err(e) = self.persist() {
            self.state = previous;
            return Err(e);
        }
        Ok(())
    }

    pub fn is_paired(&self, peer: &PeerId) -> bool {
        self.state.paired.contains_key(&peer.to_hex())
    }

    /// Every paired peer, with the note recorded at pairing time.
    pub fn paired(&self) -> Vec<(PeerId, String)> {
        self.state
            .paired
            .iter()
            .filter_map(|(hex, note)| PeerId::from_hex(hex).ok().map(|id| (id, note.clone())))
            .collect()
    }

    /// Claims the next outbound sequence number and commits it before it is used.
    ///
    /// Committed first on purpose. Crashing after publishing but before persisting would
    /// reuse the number, and the receiver would drop the resent bundle as a replay; losing
    /// a number costs nothing, since only ordering matters.
    pub fn next_sequence(&mut self) -> io::Result<u64> {
        self.commit(|state| state.outbound_sequence += 1)?;
        Ok(self.state.outbound_sequence)
    }

    pub fn outbound_sequence(&self) -> u64 {
        self.state.outbound_sequence
    }

    /// Highest sequence accepted from a peer, so replay protection survives a restart.
    pub fn inbound_cursor(&self, peer: &PeerId) -> Option<u64> {
        self.state.inbound_cursor.get(&peer.to_hex()).copied()
    }

    pub fn record_inbound(&mut self, peer: &PeerId, sequence: u64) -> io::Result<()> {
        if self
            .state
            .inbound_cursor
            .get(&peer.to_hex())
            .is_some_and(|seen| *seen >= sequence)
        {
            return Ok(());
        }
        self.commit(|state| {
            state.inbound_cursor.insert(peer.to_hex(), sequence);
        })
    }

    /// Every inbound cursor, for seeding a ledger at startup.
    pub fn inbound_cursors(&self) -> Vec<(PeerId, u64)> {
        self.state
            .inbound_cursor
            .iter()
            .filter_map(|(hex, seq)| PeerId::from_hex(hex).ok().map(|id| (id, *seq)))
            .collect()
    }

    /// Writes through a uniquely named temporary file and renames it into place.
    ///
    /// The temporary name is unique and created exclusively, so a second process -- or an
    /// attacker who guessed a fixed `.tmp` name and pre-created it as a symlink -- cannot
    /// have the write follow somewhere else or interleave with ours.
    fn persist(&mut self) -> io::Result<()> {
        let serialized = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let temporary = self.temporary_path();
        // Best effort cleanup on every failure path: a temporary left behind is a
        // world-visible copy of the identity file.
        let result = (|| {
            write_private(&temporary, &serialized)?;
            // Atomic within a filesystem, and on Windows this replaces an existing file
            // rather than failing, which a plain create-new rename would.
            replace_file(&temporary, &self.path)?;
            // The rename itself must be durable, not just the file contents: without this
            // a crash can leave the directory entry pointing at neither version.
            sync_directory(self.path.parent());
            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// A temporary path no other writer will choose.
    fn temporary_path(&self) -> PathBuf {
        // Process id plus a counter: unique between processes and between writes within
        // one, without needing a random source.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let suffix = format!("tmp.{}.{ordinal}", std::process::id());
        self.path.with_extension(suffix)
    }
}

/// Renames `from` over `to`, replacing whatever is there.
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    // `std::fs::rename` already replaces on both Unix and Windows. Named separately so the
    // requirement is explicit rather than an assumption about the platform.
    std::fs::rename(from, to)
}

/// Flushes a directory entry, so a rename survives a crash.
///
/// Unix only, and deliberately best-effort: some filesystems refuse to open a directory
/// for this and the write is still far more durable than not renaming at all.
#[cfg(unix)]
fn sync_directory(directory: Option<&Path>) {
    if let Some(directory) = directory
        && let Ok(handle) = std::fs::File::open(directory)
    {
        let _ = handle.sync_all();
    }
}

/// Windows offers no directory handle to flush this way; `MoveFileEx` durability is the
/// platform's own guarantee.
#[cfg(not(unix))]
fn sync_directory(_directory: Option<&Path>) {}

/// Writes a file only this user can read, setting the mode before the contents land.
///
/// Created exclusively, so an existing file at this path -- including a symlink an attacker
/// planted -- makes the write fail rather than land somewhere else.
#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // Set at creation rather than afterwards: a chmod after writing leaves a window in
        // which the secret is readable by everyone.
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Windows has no mode bits. The file is created exclusively inside a directory under the
/// user's own profile, which inherits that profile's ACL.
///
/// Not equivalent to 0600: an administrator, and any process running as this user, can read
/// it. Stated plainly rather than implied, because the identity seed lives here and a
/// stronger claim would be false. A future version should hold it in the platform's own
/// credential store.
#[cfg(not(unix))]
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Windows inherits the ACL of the parent, which is why the default path is inside the
/// user's own profile rather than a shared location.
#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Where federation state lives by default.
///
/// Per platform, and always inside something only this user owns -- the file holds an
/// identity seed. The temporary directory is the last resort and is noted as such: state
/// there does not reliably survive a reboot, so the identity would change.
pub fn default_path() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData/Local"))
        });

    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")));

    base.unwrap_or_else(std::env::temp_dir)
        .join("idnx")
        .join("federation.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own per test.
    ///
    /// Tests run concurrently and each cleans up its own temporaries; a shared directory
    /// meant one test could delete another's file between its write and its rename.
    fn temporary() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("idnx-store-{}-{unique}", std::process::id()))
            .join("federation.json")
    }

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Some(parent) = self.0.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
    }

    #[test]
    fn identity_survives_a_restart() {
        // A peer that regenerates its key each start looks like a new peer every time, and
        // nothing it published before can still be attributed to it.
        let path = temporary();
        let _scratch = Scratch(path.clone());

        let first = FederationStore::open(&path).expect("opens");
        let id = first.peer_id();
        drop(first);

        let second = FederationStore::open(&path).expect("reopens");
        assert_eq!(second.peer_id(), id);
    }

    #[test]
    fn pairings_survive_a_restart() {
        let path = temporary();
        let _scratch = Scratch(path.clone());
        let peer = PeerKey::generate().id();

        let mut store = FederationStore::open(&path).expect("opens");
        store.pair(&peer, "the sensor network").expect("pairs");
        drop(store);

        let store = FederationStore::open(&path).expect("reopens");
        assert!(store.is_paired(&peer));
        assert_eq!(
            store.paired(),
            vec![(peer.clone(), "the sensor network".to_string())]
        );

        let mut store = store;
        store.unpair(&peer).expect("unpairs");
        drop(store);
        assert!(
            !FederationStore::open(&path)
                .expect("reopens")
                .is_paired(&peer)
        );
    }

    #[test]
    fn the_outbound_sequence_never_repeats_across_restarts() {
        // Reusing a number the receiver already accepted makes this peer's own bundles
        // look like replays, and they are dropped without a word.
        let path = temporary();
        let _scratch = Scratch(path.clone());

        let mut store = FederationStore::open(&path).expect("opens");
        assert_eq!(store.next_sequence().expect("claims"), 1);
        assert_eq!(store.next_sequence().expect("claims"), 2);
        drop(store);

        let mut store = FederationStore::open(&path).expect("reopens");
        assert_eq!(store.next_sequence().expect("claims"), 3);
    }

    #[test]
    fn replay_protection_survives_a_restart() {
        // Otherwise a bundle captured today is accepted again after the next restart.
        let path = temporary();
        let _scratch = Scratch(path.clone());
        let peer = PeerKey::generate().id();

        let mut store = FederationStore::open(&path).expect("opens");
        store.record_inbound(&peer, 9).expect("records");
        // An older sequence must not move the cursor backwards.
        store.record_inbound(&peer, 4).expect("records");
        drop(store);

        let store = FederationStore::open(&path).expect("reopens");
        assert_eq!(store.inbound_cursor(&peer), Some(9));
        assert_eq!(store.inbound_cursors(), vec![(peer, 9)]);
    }

    #[cfg(unix)]
    #[test]
    fn the_identity_file_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let path = temporary();
        let _scratch = Scratch(path.clone());
        let _store = FederationStore::open(&path).expect("opens");

        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "group and other must have no access");
    }

    #[test]
    fn no_debug_output_reveals_the_identity_seed() {
        let path = temporary();
        let _scratch = Scratch(path.clone());
        let store = FederationStore::open(&path).expect("opens");

        let seed = encode_hex(&store.identity().seed());
        assert!(!format!("{store:?}").contains(&seed));
        assert!(!format!("{:?}", store.state).contains(&seed));
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        // A leftover temporary is a second copy of the identity file, and on a fixed name
        // it is also somewhere an attacker can plant a symlink before the next write.
        let path = temporary();
        let _scratch = Scratch(path.clone());

        let mut store = FederationStore::open(&path).expect("opens");
        store.next_sequence().expect("claims");
        store.next_sequence().expect("claims");

        let leftovers: Vec<String> = std::fs::read_dir(path.parent().unwrap())
            .expect("reads")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_failed_write_leaves_memory_and_disk_agreeing() {
        // Otherwise this process believes a peer is paired while the next start disagrees,
        // and the two views diverge with nothing to indicate it.
        let path = temporary();
        let _scratch = Scratch(path.clone());
        let mut store = FederationStore::open(&path).expect("opens");
        let peer = PeerKey::generate().id();

        // Make the write fail by turning the state file's directory into a dead end.
        let saved = store.path.clone();
        store.path = saved.join("does").join("not").join("exist.json");

        assert!(store.pair(&peer, "note").is_err());
        assert!(
            !store.is_paired(&peer),
            "the in-memory change must be rolled back"
        );

        store.path = saved;
        assert!(store.pair(&peer, "note").is_ok());
        assert!(store.is_paired(&peer));
    }

    #[test]
    fn a_corrupt_state_file_is_an_error_rather_than_a_fresh_identity() {
        // Starting over would discard every pairing the operator made and silently change
        // who this machine claims to be.
        let path = temporary();
        let _scratch = Scratch(path.clone());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();

        let error = FederationStore::open(&path).expect_err("must not start over");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_state_file_with_an_unusable_seed_is_an_error() {
        let path = temporary();
        let _scratch = Scratch(path.clone());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, br#"{"identity_seed":"zzzz"}"#).unwrap();
        assert!(FederationStore::open(&path).is_err());
    }
}
