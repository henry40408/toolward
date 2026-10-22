//! Caching hints of list results (`ttlMs` and `cacheScope`, SEP-2549).
//!
//! toolward does not cache upstream results itself. The agent does, so a
//! second cache here would let a result stay fresh for twice its `ttlMs`.
//! Instead the proxy tells the agent the weakest hint of everything a merged
//! result was built from.

use std::future::Future;

use rmcp::model::{CacheScope, Cursor, PaginatedRequestParams, Prompt, Resource, Tool};
use rmcp::service::{Peer, RoleClient, ServiceError};

/// How long and for whom a result may be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheHint {
    pub ttl_ms: u64,
    pub scope: CacheScope,
}

impl CacheHint {
    /// Immediately stale and not shareable. This is also what a result without
    /// hints, from a server older than 2026-07-28, is treated as.
    pub const UNCACHEABLE: Self = Self {
        ttl_ms: 0,
        scope: CacheScope::Private,
    };

    pub fn of_result(ttl_ms: Option<u64>, scope: Option<CacheScope>) -> Self {
        Self {
            ttl_ms: ttl_ms.unwrap_or(0),
            scope: scope.unwrap_or(CacheScope::Private),
        }
    }

    /// The hint that holds for data from both sources.
    pub fn weakest(self, other: Self) -> Self {
        let scope = if self.scope == CacheScope::Public && other.scope == CacheScope::Public {
            CacheScope::Public
        } else {
            CacheScope::Private
        };
        Self {
            ttl_ms: self.ttl_ms.min(other.ttl_ms),
            scope,
        }
    }
}

/// The hint for a result merged from several listings. Nothing to merge is
/// uncacheable, because no upstream vouches for the result.
pub fn weakest_of(hints: impl IntoIterator<Item = CacheHint>) -> CacheHint {
    hints
        .into_iter()
        .reduce(CacheHint::weakest)
        .unwrap_or(CacheHint::UNCACHEABLE)
}

/// A complete listing and the hint it may be cached with.
#[derive(Debug)]
pub struct Listed<T> {
    pub items: Vec<T>,
    pub hint: CacheHint,
}

struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<Cursor>,
    hint: CacheHint,
}

/// Follows `next_cursor` to the end. The hint is the weakest of all pages.
async fn collect_pages<T, Fut>(
    fetch_page: impl Fn(Option<Cursor>) -> Fut,
) -> Result<Listed<T>, ServiceError>
where
    Fut: Future<Output = Result<Page<T>, ServiceError>>,
{
    let mut items = Vec::new();
    let mut hints = Vec::new();
    let mut cursor = None;
    loop {
        let page = fetch_page(cursor).await?;
        items.extend(page.items);
        hints.push(page.hint);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(Listed {
        items,
        hint: weakest_of(hints),
    })
}

fn first_page(cursor: Option<Cursor>) -> Option<PaginatedRequestParams> {
    Some(PaginatedRequestParams::default().with_cursor(cursor))
}

pub async fn list_tools(peer: &Peer<RoleClient>) -> Result<Listed<Tool>, ServiceError> {
    collect_pages(|cursor| async move {
        let result = peer.list_tools(first_page(cursor)).await?;
        Ok(Page {
            items: result.tools,
            next_cursor: result.next_cursor,
            hint: CacheHint::of_result(result.ttl_ms, result.cache_scope),
        })
    })
    .await
}

pub async fn list_resources(peer: &Peer<RoleClient>) -> Result<Listed<Resource>, ServiceError> {
    collect_pages(|cursor| async move {
        let result = peer.list_resources(first_page(cursor)).await?;
        Ok(Page {
            items: result.resources,
            next_cursor: result.next_cursor,
            hint: CacheHint::of_result(result.ttl_ms, result.cache_scope),
        })
    })
    .await
}

pub async fn list_prompts(peer: &Peer<RoleClient>) -> Result<Listed<Prompt>, ServiceError> {
    collect_pages(|cursor| async move {
        let result = peer.list_prompts(first_page(cursor)).await?;
        Ok(Page {
            items: result.prompts,
            next_cursor: result.next_cursor,
            hint: CacheHint::of_result(result.ttl_ms, result.cache_scope),
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_60S: CacheHint = CacheHint {
        ttl_ms: 60_000,
        scope: CacheScope::Public,
    };
    const PRIVATE_5S: CacheHint = CacheHint {
        ttl_ms: 5_000,
        scope: CacheScope::Private,
    };

    #[test]
    fn a_result_without_hints_is_uncacheable() {
        assert_eq!(CacheHint::of_result(None, None), CacheHint::UNCACHEABLE);
    }

    #[test]
    fn the_weakest_hint_has_the_shortest_ttl_and_the_narrowest_scope() {
        let merged = PUBLIC_60S.weakest(PRIVATE_5S);
        assert_eq!(merged, PRIVATE_5S);
        assert_eq!(PRIVATE_5S.weakest(PUBLIC_60S), merged);
        assert_eq!(PUBLIC_60S.weakest(PUBLIC_60S), PUBLIC_60S);
        // A short public hint does not make a long private one public.
        let short_public = CacheHint {
            ttl_ms: 1,
            scope: CacheScope::Public,
        };
        let long_private = CacheHint {
            ttl_ms: 90_000,
            scope: CacheScope::Private,
        };
        assert_eq!(
            short_public.weakest(long_private),
            CacheHint {
                ttl_ms: 1,
                scope: CacheScope::Private
            }
        );
    }

    fn page(next: Option<&str>, hint: CacheHint) -> Page<u8> {
        Page {
            items: vec![1],
            next_cursor: next.map(str::to_owned),
            hint,
        }
    }

    #[tokio::test]
    async fn pages_are_followed_and_their_hints_merged() {
        let listed = collect_pages(|cursor| async move {
            Ok(match cursor.as_deref() {
                None => page(Some("b"), PUBLIC_60S),
                Some("b") => page(Some("c"), PRIVATE_5S),
                _ => page(None, PUBLIC_60S),
            })
        })
        .await
        .unwrap();
        assert_eq!(listed.items, [1, 1, 1]);
        assert_eq!(listed.hint, PRIVATE_5S);
    }
}
