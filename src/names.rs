//! Names the agent sees for upstream tools.
//!
//! A tool is exposed as `<server>__<tool>`. Clients prepend their own prefix
//! (`mcp__toolward__` in Claude Code) and some cap the whole name at 64
//! characters, so the part toolward controls is kept within [`BUDGET`].
//! Names that are too long, or that contain characters some clients rewrite,
//! become `<server>__<stem>_<hash>`, where the hash is derived from the
//! original name. A name that collides with another one gets a longer hash, so
//! adding a tool can rename another tool that collides with it.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Separates the server name from the tool name. Server names cannot contain it.
pub const SEPARATOR: &str = "__";
/// Longest `<server>__<tool>` toolward emits: 64 minus the 15 characters of
/// `mcp__toolward__`, the strictest client we know of (pi).
pub const BUDGET: usize = 49;
/// Characters of the base32 hash suffix. 8 characters are 40 bits.
pub const HASH_LEN: usize = 8;
/// A SHA-256 digest holds 51 whole base32 characters.
const MAX_HASH_LEN: usize = 51;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Replaces every character outside `[A-Za-z0-9_-]` with `_`.
pub fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn base32_prefix(digest: &[u8], len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in digest {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            if out.len() == len {
                return out;
            }
        }
        buffer &= (1 << bits) - 1;
    }
    out
}

fn sha256(server: &str, tool: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(server.as_bytes());
    hasher.update([0]);
    hasher.update(tool.as_bytes());
    hasher.finalize().to_vec()
}

/// Cuts `stem` (ASCII) to at most `max` bytes, preferring a `_` boundary.
fn truncate_stem(stem: &str, max: usize) -> &str {
    if stem.len() <= max {
        return stem;
    }
    let cut = &stem[..max];
    match cut.rfind('_') {
        Some(index) if index > 0 => &cut[..index],
        _ => cut,
    }
}

struct Entry<'a> {
    original: &'a str,
    stem: String,
    /// The original name is used as is.
    plain: bool,
    hash_len: usize,
    digest: Vec<u8>,
}

impl Entry<'_> {
    fn exposed(&self, room: usize) -> String {
        if self.plain {
            return self.original.to_owned();
        }
        let hash = base32_prefix(&self.digest, self.hash_len);
        let available = room.saturating_sub(self.hash_len + 1).max(1);
        format!("{}_{hash}", truncate_stem(&self.stem, available))
    }
}

/// The result of naming one server's tools.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Assignment {
    /// `(exposed tool part, original tool name)` in input order. The agent
    /// sees `<server>__<exposed tool part>`.
    pub names: Vec<(String, String)>,
    /// Original names that could not get a unique exposed name.
    pub dropped: Vec<String>,
}

/// Names the tools of `server`. `originals` are the names the upstream reports.
pub fn assign(server: &str, originals: &[String]) -> Assignment {
    assign_with(server, originals, sha256)
}

/// A longer hash separates names that collide. Each round grows the hash of
/// every colliding hashed name; the loop ends when nothing can grow. Returns,
/// per entry, whether it was dropped because it still collides.
fn widen_colliding_hashes(entries: &mut [Entry], room: usize, max_hash_len: usize) -> Vec<bool> {
    let mut dropped = vec![false; entries.len()];
    loop {
        let mut seen: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if !dropped[index] {
                seen.entry(entry.exposed(room)).or_default().push(index);
            }
        }
        let mut changed = false;
        for group in seen.values().filter(|group| group.len() > 1) {
            for &index in group {
                let entry = &mut entries[index];
                if !entry.plain && entry.hash_len < max_hash_len {
                    entry.hash_len = (entry.hash_len + 4).min(max_hash_len);
                    changed = true;
                }
            }
        }
        if changed {
            continue;
        }
        // Whatever still collides cannot be told apart: keep the first.
        for group in seen.values().filter(|group| group.len() > 1) {
            for &index in &group[1..] {
                dropped[index] = true;
            }
        }
        return dropped;
    }
}

fn assign_with(
    server: &str,
    originals: &[String],
    digest: impl Fn(&str, &str) -> Vec<u8>,
) -> Assignment {
    let room = BUDGET.saturating_sub(server.len() + SEPARATOR.len());
    let max_hash_len = MAX_HASH_LEN.min(room.saturating_sub(2)).max(1);
    let mut entries: Vec<Entry> = originals
        .iter()
        .map(|original| {
            let mut stem = sanitize(original);
            let plain = !original.is_empty() && stem == *original && original.len() <= room;
            if stem.is_empty() {
                stem.push('_');
            }
            Entry {
                original,
                stem,
                plain,
                hash_len: HASH_LEN.min(max_hash_len),
                digest: digest(server, original),
            }
        })
        .collect();

    let dropped = widen_colliding_hashes(&mut entries, room, max_hash_len);

    let mut assignment = Assignment::default();
    for (index, entry) in entries.iter().enumerate() {
        if dropped[index] {
            assignment.dropped.push(entry.original.to_owned());
        } else {
            assignment
                .names
                .push((entry.exposed(room), entry.original.to_owned()));
        }
    }
    assignment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(server: &str, originals: &[&str]) -> Vec<(String, String)> {
        let originals: Vec<String> = originals.iter().map(|s| (*s).to_owned()).collect();
        assign(server, &originals).names
    }

    #[test]
    fn short_clean_names_are_unchanged() {
        assert_eq!(
            names("github", &["get_issue", "list-prs"]),
            [
                ("get_issue".to_owned(), "get_issue".to_owned()),
                ("list-prs".to_owned(), "list-prs".to_owned()),
            ]
        );
    }

    #[test]
    fn long_names_fit_the_budget_and_end_in_a_hash() {
        let original = "create_pull_request_review_comment_thread_reply";
        let result = names("github", &[original]);
        let (exposed, _) = &result[0];
        let full = format!("github{SEPARATOR}{exposed}");
        assert!(full.len() <= BUDGET, "{full}");
        assert!(exposed.starts_with("create_pull_request"), "{exposed}");
        let (stem, hash) = exposed.rsplit_once('_').unwrap();
        assert_eq!(hash.len(), HASH_LEN);
        assert!(hash.bytes().all(|b| ALPHABET.contains(&b)));
        assert!(original.starts_with(stem));
    }

    #[test]
    fn names_are_stable_and_depend_on_the_server() {
        let original = "create_pull_request_review_comment_thread_reply";
        assert_eq!(names("github", &[original]), names("github", &[original]));
        assert_ne!(names("github", &[original]), names("gitlab", &[original]));
    }

    #[test]
    fn names_sharing_a_prefix_stay_apart() {
        let result = names(
            "github",
            &[
                "create_pull_request_review_comment_thread_reply",
                "create_pull_request_review_comment_thread_resolve",
            ],
        );
        assert_ne!(result[0].0, result[1].0);
    }

    #[test]
    fn unsafe_characters_are_replaced_and_hashed() {
        let result = names("s", &["a.b", "a:b", "a_b"]);
        assert!(result[0].0.starts_with("a_b_"));
        assert!(result[1].0.starts_with("a_b_"));
        assert_ne!(result[0].0, result[1].0);
        // The clean name is left alone and cannot collide with the others.
        assert_eq!(result[2].0, "a_b");
        for (exposed, _) in &result {
            assert!(sanitize(exposed) == *exposed);
        }
    }

    #[test]
    fn a_name_at_the_budget_edge_is_kept() {
        let room = BUDGET - "s".len() - SEPARATOR.len();
        let fits = "a".repeat(room);
        let over = "a".repeat(room + 1);
        let result = names("s", &[&fits, &over]);
        assert_eq!(result[0].0, fits);
        assert_ne!(result[1].0, over);
        assert!(format!("s__{}", result[1].0).len() <= BUDGET);
    }

    #[test]
    fn collisions_are_resolved_with_a_longer_hash() {
        // Digests that agree in the first 40 bits (8 characters) only.
        let digest = |_: &str, tool: &str| {
            let mut bytes = vec![0u8; 32];
            if tool.contains(':') {
                bytes[5] = 0xff;
            }
            bytes
        };
        // Both sanitize to the same stem "a_x".
        let originals = vec!["a.x".to_owned(), "a:x".to_owned()];
        let result = assign_with("s", &originals, digest);
        assert!(result.dropped.is_empty());
        assert_ne!(result.names[0].0, result.names[1].0);
        assert!(result.names[0].0.len() > "a_x_".len() + HASH_LEN);
    }

    #[test]
    fn indistinguishable_names_are_dropped() {
        let originals = vec!["dup".to_owned(), "dup".to_owned()];
        let result = assign("s", &originals);
        assert_eq!(result.names.len(), 1);
        assert_eq!(result.dropped, ["dup"]);
    }

    #[test]
    fn empty_names_do_not_panic() {
        let result = names("s", &[""]);
        assert!(result[0].0.starts_with("__") || result[0].0.starts_with('_'));
    }

    #[test]
    fn base32_prefix_uses_the_lowercase_alphabet() {
        assert_eq!(base32_prefix(&[0, 0, 0, 0, 0], 8), "aaaaaaaa");
        assert_eq!(base32_prefix(&[0xff; 5], 8), "77777777");
        assert_eq!(base32_prefix(&[0xff; 5], 3), "777");
    }
}
