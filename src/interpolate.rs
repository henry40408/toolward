//! `${keychain:<account>}` interpolation for config strings.
//!
//! * `${keychain:name}` is replaced with the secret stored under `name`.
//! * `$${` is an escape for a literal `${`.
//! * Any other `${...}` is rejected so typos never reach an upstream verbatim.

use crate::store::{CredentialStore, StoreError, validate_account};

#[derive(Debug, thiserror::Error)]
pub enum InterpolateError {
    // Messages never quote the config text: it may already contain a literal secret.
    #[error("unterminated '${{' reference")]
    Unterminated,
    #[error("unsupported '${{...}}' reference: only '${{keychain:<account>}}' is supported")]
    Unsupported,
    #[error("no secret stored for account {0:?}; run `toolward secret set {0}`")]
    Missing(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, PartialEq, Eq)]
enum Segment<'a> {
    Literal(String),
    Keychain(&'a str),
}

fn parse(input: &str) -> Result<Vec<Segment<'_>>, InterpolateError> {
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut rest = input;
    while let Some(pos) = rest.find('$') {
        literal.push_str(&rest[..pos]);
        rest = &rest[pos..];
        if let Some(after) = rest.strip_prefix("$${") {
            literal.push_str("${");
            rest = after;
        } else if let Some(after) = rest.strip_prefix("${") {
            let end = after.find('}').ok_or(InterpolateError::Unterminated)?;
            let body = &after[..end];
            let account = body
                .strip_prefix("keychain:")
                .ok_or(InterpolateError::Unsupported)?;
            validate_account(account)?;
            if !literal.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut literal)));
            }
            segments.push(Segment::Keychain(account));
            rest = &after[end + 1..];
        } else {
            literal.push('$');
            rest = &rest[1..];
        }
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        segments.push(Segment::Literal(literal));
    }
    Ok(segments)
}

/// Lists the accounts referenced by `input`, in order of appearance.
pub fn references(input: &str) -> Result<Vec<String>, InterpolateError> {
    Ok(parse(input)?
        .into_iter()
        .filter_map(|segment| match segment {
            Segment::Keychain(account) => Some(account.to_owned()),
            Segment::Literal(_) => None,
        })
        .collect())
}

/// Expands every reference in `input` using `store`.
pub fn expand(input: &str, store: &dyn CredentialStore) -> Result<String, InterpolateError> {
    let mut out = String::new();
    for segment in parse(input)? {
        match segment {
            Segment::Literal(text) => out.push_str(&text),
            Segment::Keychain(account) => {
                let secret = store
                    .get(account)?
                    .ok_or_else(|| InterpolateError::Missing(account.to_owned()))?;
                out.push_str(&secret);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn store() -> MemoryStore {
        MemoryStore::with(&[("gh", "ghp_abc"), ("b", "B")])
    }

    #[test]
    fn plain_strings_pass_through() {
        assert_eq!(
            expand("hello $ world $5", &store()).unwrap(),
            "hello $ world $5"
        );
        assert_eq!(expand("", &store()).unwrap(), "");
    }

    #[test]
    fn expands_references_inline() {
        assert_eq!(
            expand("Bearer ${keychain:gh}", &store()).unwrap(),
            "Bearer ghp_abc"
        );
        assert_eq!(
            expand("${keychain:gh}:${keychain:b}!", &store()).unwrap(),
            "ghp_abc:B!"
        );
    }

    #[test]
    fn escape_yields_literal() {
        assert_eq!(
            expand("$${keychain:gh}", &store()).unwrap(),
            "${keychain:gh}"
        );
    }

    #[test]
    fn secret_value_is_not_reinterpreted() {
        let store = MemoryStore::with(&[("x", "${keychain:y}")]);
        assert_eq!(expand("${keychain:x}", &store).unwrap(), "${keychain:y}");
    }

    #[test]
    fn rejects_unsupported_and_malformed() {
        assert!(matches!(
            expand("${HOME}", &store()),
            Err(InterpolateError::Unsupported)
        ));
        assert!(matches!(
            expand("${keychain:gh", &store()),
            Err(InterpolateError::Unterminated)
        ));
        assert!(matches!(
            expand("${keychain:bad name}", &store()),
            Err(InterpolateError::Store(StoreError::InvalidAccount(_)))
        ));
    }

    #[test]
    fn missing_secret_names_the_account() {
        match expand("${keychain:nope}", &store()) {
            Err(InterpolateError::Missing(account)) => assert_eq!(account, "nope"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn lists_references_without_touching_the_store() {
        assert_eq!(
            references("a ${keychain:x} $${keychain:no} ${keychain:y}").unwrap(),
            ["x", "y"]
        );
    }
}
