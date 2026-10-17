use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_VERSION");
    let in_repo = in_own_repo();
    if in_repo {
        // `.git` is a file inside a worktree, so ask git where HEAD, its reflog and the tags live.
        // A path that does not exist would make Cargo rebuild on every run, so skip those.
        for name in ["HEAD", "logs/HEAD", "index", "refs/tags", "packed-refs"] {
            if let Some(path) = git(&["rev-parse", "--git-path", name])
                && Path::new(&path).exists()
            {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    println!("cargo:rustc-env=GIT_VERSION={}", version(in_repo));
}

/// True when the crate is the root of its own git checkout. A registry or vendored copy
/// may sit inside an unrelated repository, whose version must not leak into the binary.
fn in_own_repo() -> bool {
    let Some(top) = git(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    match (
        PathBuf::from(top).canonicalize(),
        PathBuf::from(manifest_dir).canonicalize(),
    ) {
        (Ok(top), Ok(manifest_dir)) => top == manifest_dir,
        _ => false,
    }
}

/// `GIT_VERSION` when set (for builds without a `.git` directory), else `git describe`,
/// else the crate version.
fn version(in_repo: bool) -> String {
    if let Ok(version) = std::env::var("GIT_VERSION")
        && !version.is_empty()
        && version != "dev"
    {
        return version;
    }
    // --always falls back to the commit hash when no tag exists; --dirty marks local edits.
    in_repo
        .then(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .flatten()
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "dev".into()))
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}
