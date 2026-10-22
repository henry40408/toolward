//! Credential storage backends.
//!
//! Secrets are addressed by an *account* name. Config files only ever hold
//! references to accounts, never the secret values.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Keychain service under which every toolward secret is stored.
pub const SERVICE: &str = "toolward";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid account name {0:?}: use only ASCII letters, digits, '.', '_' and '-'")]
    InvalidAccount(String),
    #[error(
        "account names starting with \"oauth.\" or \"oauth-client.\" are reserved for OAuth logins: {0:?}"
    )]
    Reserved(String),
    #[error("credential store failure: {0}")]
    Backend(String),
    #[error("no credential store is available on this platform")]
    Unsupported,
}

/// Validates an account name. The same charset is accepted inside `${keychain:...}`.
pub fn validate_account(account: &str) -> Result<(), StoreError> {
    let ok = !account.is_empty()
        && account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(StoreError::InvalidAccount(account.to_owned()))
    }
}

/// Account prefixes that only `toolward auth login` may write: the tokens
/// (`oauth.`) and a dynamically registered client secret (`oauth-client.`).
pub const RESERVED_PREFIXES: [&str; 2] = ["oauth.", "oauth-client."];

/// Like [`validate_account`], for names a user picks: the reserved prefixes
/// are for what `toolward auth login` stores.
pub fn validate_user_account(account: &str) -> Result<(), StoreError> {
    validate_account(account)?;
    if RESERVED_PREFIXES.iter().any(|p| account.starts_with(p)) {
        return Err(StoreError::Reserved(account.to_owned()));
    }
    Ok(())
}

pub trait CredentialStore: Send + Sync {
    /// Returns `None` when the account has no secret.
    fn get(&self, account: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError>;
    /// Returns `true` when a secret existed and was removed.
    fn delete(&self, account: &str) -> Result<bool, StoreError>;
}

/// OS-backed store built on `keyring-core`.
pub struct KeyringStore {
    store: std::sync::Arc<keyring_core::CredentialStore>,
}

impl KeyringStore {
    /// macOS Keychain.
    #[cfg(target_os = "macos")]
    pub fn native() -> Result<Self, StoreError> {
        let store = apple_native_keyring_store::keychain::Store::new().map_err(backend)?;
        Ok(Self { store })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn native() -> Result<Self, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Wraps any `keyring-core` store. Used with the mock store in tests.
    pub fn from_store(store: std::sync::Arc<keyring_core::CredentialStore>) -> Self {
        Self { store }
    }

    fn entry(&self, account: &str) -> Result<keyring_core::Entry, StoreError> {
        validate_account(account)?;
        self.store.build(SERVICE, account, None).map_err(backend)
    }
}

fn backend(err: keyring_core::Error) -> StoreError {
    StoreError::Backend(err.to_string())
}

impl CredentialStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<String>, StoreError> {
        match self.entry(account)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(backend(err)),
        }
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError> {
        self.entry(account)?.set_password(secret).map_err(backend)
    }

    fn delete(&self, account: &str) -> Result<bool, StoreError> {
        match self.entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(err) => Err(backend(err)),
        }
    }
}

/// Reads each account from the inner store at most once and one at a time.
///
/// Upstreams connect concurrently and each `${keychain:...}` reference would
/// otherwise open its own OS authorization prompt. Holding the lock across the
/// read queues the prompts, and the cache stops a repeated account from
/// prompting again. An entry expires after [`CACHE_TTL`], so a rotated secret
/// is picked up on a later reconnect. A missing secret is never cached.
pub struct CachedStore<S> {
    inner: S,
    cache: Mutex<HashMap<String, (Instant, String)>>,
    ttl: Duration,
}

/// Long enough to cover the concurrent connections at startup.
const CACHE_TTL: Duration = Duration::from_secs(60);

impl<S: CredentialStore> CachedStore<S> {
    pub fn new(inner: S) -> Self {
        Self::with_ttl(inner, CACHE_TTL)
    }

    fn with_ttl(inner: S, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Mutex::default(),
            ttl,
        }
    }

    /// A panic in the backend must not make every later read panic too.
    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Instant, String)>> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<S: CredentialStore> CredentialStore for CachedStore<S> {
    fn get(&self, account: &str) -> Result<Option<String>, StoreError> {
        validate_account(account)?;
        let mut cache = self.cache();
        if let Some((read_at, secret)) = cache.get(account)
            && read_at.elapsed() < self.ttl
        {
            return Ok(Some(secret.clone()));
        }
        cache.remove(account);
        // Routine reads stay silent. Log only a failure, and never the secret.
        let secret = self.inner.get(account).inspect_err(|err| {
            eprintln!("toolward: reading credential store account {account:?} failed: {err}");
        })?;
        if let Some(secret) = &secret {
            cache.insert(account.to_owned(), (Instant::now(), secret.clone()));
        }
        Ok(secret)
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError> {
        // Hold the lock across the write so a concurrent read cannot cache the old value.
        let mut cache = self.cache();
        cache.remove(account);
        self.inner.set(account, secret)
    }

    fn delete(&self, account: &str) -> Result<bool, StoreError> {
        let mut cache = self.cache();
        cache.remove(account);
        self.inner.delete(account)
    }
}

/// In-memory store for tests.
#[derive(Default)]
pub struct MemoryStore {
    secrets: Mutex<HashMap<String, String>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(entries: &[(&str, &str)]) -> Self {
        let store = Self::new();
        for (account, secret) in entries {
            store.set(account, secret).expect("valid test account");
        }
        store
    }
}

impl CredentialStore for MemoryStore {
    fn get(&self, account: &str) -> Result<Option<String>, StoreError> {
        validate_account(account)?;
        Ok(self.secrets.lock().unwrap().get(account).cloned())
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), StoreError> {
        validate_account(account)?;
        self.secrets
            .lock()
            .unwrap()
            .insert(account.to_owned(), secret.to_owned());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<bool, StoreError> {
        validate_account(account)?;
        Ok(self.secrets.lock().unwrap().remove(account).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_validation() {
        for ok in ["github", "a.b_c-1"] {
            assert!(validate_account(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "a/b", "a:b", "${x}", "é"] {
            assert!(validate_account(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryStore::new();
        assert_eq!(store.get("a").unwrap(), None);
        store.set("a", "s3cret").unwrap();
        assert_eq!(store.get("a").unwrap().as_deref(), Some("s3cret"));
        assert!(store.delete("a").unwrap());
        assert!(!store.delete("a").unwrap());
        assert_eq!(store.get("a").unwrap(), None);
    }

    /// Counts reads and notes whether two reads overlapped.
    #[derive(Default)]
    struct Probe {
        reads: std::sync::atomic::AtomicUsize,
        active: std::sync::atomic::AtomicUsize,
        overlapped: std::sync::atomic::AtomicBool,
    }

    impl CredentialStore for Probe {
        fn get(&self, _account: &str) -> Result<Option<String>, StoreError> {
            use std::sync::atomic::Ordering::SeqCst;
            self.reads.fetch_add(1, SeqCst);
            if self.active.fetch_add(1, SeqCst) > 0 {
                self.overlapped.store(true, SeqCst);
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
            self.active.fetch_sub(1, SeqCst);
            Ok(Some("s3cret".into()))
        }

        fn set(&self, _: &str, _: &str) -> Result<(), StoreError> {
            Ok(())
        }

        fn delete(&self, _: &str) -> Result<bool, StoreError> {
            Ok(true)
        }
    }

    #[test]
    fn cached_store_reads_once_and_one_at_a_time() {
        use std::sync::atomic::Ordering::SeqCst;
        let store = std::sync::Arc::new(CachedStore::new(Probe::default()));
        let threads: Vec<_> = (0..6)
            .map(|i| {
                let store = std::sync::Arc::clone(&store);
                // Two distinct accounts, each asked for three times.
                std::thread::spawn(move || store.get(&format!("acct{}", i % 2)).unwrap())
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap().as_deref(), Some("s3cret"));
        }
        assert_eq!(store.inner.reads.load(SeqCst), 2);
        assert!(!store.inner.overlapped.load(SeqCst));
    }

    #[test]
    fn cached_store_forgets_an_account_after_set() {
        use std::sync::atomic::Ordering::SeqCst;
        let store = CachedStore::new(Probe::default());
        store.get("a").unwrap();
        store.set("a", "new").unwrap();
        store.get("a").unwrap();
        assert_eq!(store.inner.reads.load(SeqCst), 2);
    }

    #[test]
    fn cached_store_forgets_an_account_after_delete() {
        use std::sync::atomic::Ordering::SeqCst;
        let store = CachedStore::new(Probe::default());
        store.get("a").unwrap();
        store.delete("a").unwrap();
        store.get("a").unwrap();
        assert_eq!(store.inner.reads.load(SeqCst), 2);
    }

    #[test]
    fn cached_store_does_not_remember_a_missing_secret() {
        let store = CachedStore::new(MemoryStore::new());
        assert_eq!(store.get("late").unwrap(), None);
        // Stored behind the cache's back, as `toolward secret set` would.
        store.inner.set("late", "now").unwrap();
        assert_eq!(store.get("late").unwrap().as_deref(), Some("now"));
    }

    #[test]
    fn cached_store_rereads_once_after_expiry_then_caches_again() {
        use std::sync::atomic::Ordering::SeqCst;
        let ttl = std::time::Duration::from_millis(50);
        // Deterministic bounds: a zero TTL never caches, a huge one always does.
        let never = CachedStore::with_ttl(Probe::default(), std::time::Duration::ZERO);
        never.get("a").unwrap();
        never.get("a").unwrap();
        assert_eq!(never.inner.reads.load(SeqCst), 2);
        let always = CachedStore::with_ttl(Probe::default(), std::time::Duration::from_secs(3600));
        always.get("a").unwrap();
        always.get("a").unwrap();
        assert_eq!(always.inner.reads.load(SeqCst), 1);
        let store = CachedStore::with_ttl(Probe::default(), ttl);
        store.get("a").unwrap();
        assert_eq!(store.inner.reads.load(SeqCst), 1);
        std::thread::sleep(ttl * 3);
        // First read after expiry hits the inner store once...
        assert_eq!(store.get("a").unwrap().as_deref(), Some("s3cret"));
        assert_eq!(store.inner.reads.load(SeqCst), 2);
        // ...and later reads are served from the cache again.
        for _ in 0..5 {
            assert_eq!(store.get("a").unwrap().as_deref(), Some("s3cret"));
        }
        assert_eq!(store.inner.reads.load(SeqCst), 2);
    }

    #[derive(Default)]
    struct Failing {
        reads: std::sync::atomic::AtomicUsize,
    }

    impl CredentialStore for Failing {
        fn get(&self, _: &str) -> Result<Option<String>, StoreError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(StoreError::Backend("boom".into()))
        }

        fn set(&self, _: &str, _: &str) -> Result<(), StoreError> {
            Ok(())
        }

        fn delete(&self, _: &str) -> Result<bool, StoreError> {
            Ok(false)
        }
    }

    #[test]
    fn cached_store_does_not_cache_an_inner_failure() {
        let store = CachedStore::new(Failing::default());
        assert!(store.get("a").is_err());
        assert!(store.get("a").is_err());
        assert_eq!(
            store.inner.reads.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[test]
    fn keyring_store_round_trip_with_mock() {
        let store = KeyringStore::from_store(keyring_core::mock::Store::new().unwrap());
        assert_eq!(store.get("a").unwrap(), None);
        store.set("a", "s3cret").unwrap();
        assert_eq!(store.get("a").unwrap().as_deref(), Some("s3cret"));
        assert!(store.delete("a").unwrap());
        assert!(!store.delete("a").unwrap());
    }

    #[test]
    fn oauth_accounts_are_reserved_for_logins() {
        assert!(validate_user_account("oauth.sentry").is_err());
        assert!(validate_user_account("oauth-client.sentry").is_err());
        assert!(validate_account("oauth-client.sentry").is_ok());
        assert!(validate_user_account("github").is_ok());
        assert!(validate_account("oauth.sentry").is_ok());
    }

    #[test]
    fn keyring_store_rejects_bad_account() {
        let store = KeyringStore::from_store(keyring_core::mock::Store::new().unwrap());
        assert!(matches!(
            store.set("bad/name", "x"),
            Err(StoreError::InvalidAccount(_))
        ));
    }
}
