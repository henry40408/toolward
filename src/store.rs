//! Credential storage backends.
//!
//! Secrets are addressed by an *account* name. Config files only ever hold
//! references to accounts, never the secret values.

use std::collections::HashMap;
use std::sync::Mutex;

/// Keychain service under which every toolward secret is stored.
pub const SERVICE: &str = "toolward";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid account name {0:?}: use only ASCII letters, digits, '.', '_' and '-'")]
    InvalidAccount(String),
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

pub trait CredentialStore {
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
    fn keyring_store_rejects_bad_account() {
        let store = KeyringStore::from_store(keyring_core::mock::Store::new().unwrap());
        assert!(matches!(
            store.set("bad/name", "x"),
            Err(StoreError::InvalidAccount(_))
        ));
    }
}
