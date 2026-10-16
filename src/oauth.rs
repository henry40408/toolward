//! OAuth 2.0 for HTTP upstreams.
//!
//! `toolward auth login <server>` runs the authorization-code flow once (PKCE,
//! loopback redirect on a random port) and stores the tokens in the credential
//! store. `toolward serve` only reads them, refreshes them when they expire,
//! and never opens a browser.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::auth::{
    AuthClient, AuthError, AuthorizationManager, AuthorizationRequest, AuthorizationSession,
    CredentialStore as RmcpCredentialStore, OAuthClientConfig, StoredCredentials,
};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::OAuthConfig;
use crate::interpolate;
use crate::store::{CredentialStore, validate_account};
use crate::upstream::{BoxFuture, Connect, RunningClient, UpstreamHandler, redact};

/// How long `auth login` waits for the browser to come back.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// The credential-store account that holds a server's OAuth tokens.
pub fn account_for(server: &str) -> Result<String, String> {
    let account = format!("oauth.{server}");
    validate_account(&account).map_err(|_| {
        format!("server name {server:?} cannot be used with oauth: use only ASCII letters, digits, '.', '_' and '-'")
    })?;
    Ok(account)
}

/// Keeps rmcp's token record as one JSON entry in the credential store.
/// Error text never contains the record.
pub struct TokenStore {
    store: Arc<dyn CredentialStore>,
    account: String,
    /// Serializes refreshes within this process.
    refresh: Arc<tokio::sync::Mutex<()>>,
    /// Told about the tokens of every record saved, so they can be masked.
    on_save: Option<Arc<dyn Fn(Vec<String>) + Send + Sync>>,
}

impl TokenStore {
    pub fn new(store: Arc<dyn CredentialStore>, account: String) -> Self {
        Self {
            store,
            account,
            refresh: Arc::default(),
            on_save: None,
        }
    }

    pub fn on_save(mut self, callback: impl Fn(Vec<String>) + Send + Sync + 'static) -> Self {
        self.on_save = Some(Arc::new(callback));
        self
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn CredentialStore, &str) -> Result<T, crate::store::StoreError>
        + Send
        + 'static,
    ) -> Result<T, AuthError> {
        let store = Arc::clone(&self.store);
        let account = self.account.clone();
        tokio::task::spawn_blocking(move || work(store.as_ref(), &account))
            .await
            .map_err(|err| AuthError::CredentialStoreError(err.to_string()))?
            .map_err(|err| AuthError::CredentialStoreError(err.to_string()))
    }
}

#[async_trait]
impl RmcpCredentialStore for TokenStore {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        let Some(json) = self.blocking(|store, account| store.get(account)).await? else {
            return Ok(None);
        };
        // serde errors can quote the input, so say nothing about the cause.
        serde_json::from_str(&json).map(Some).map_err(|_| {
            AuthError::CredentialStoreError(
                "the stored OAuth tokens are unreadable; run `toolward auth login` again".into(),
            )
        })
    }

    async fn save(&self, credentials: StoredCredentials) -> Result<(), AuthError> {
        let json = serde_json::to_string(&credentials)
            .map_err(|_| AuthError::CredentialStoreError("cannot encode OAuth tokens".into()))?;
        let tokens = token_values(&credentials);
        self.blocking(move |store, account| store.set(account, &json))
            .await?;
        if let Some(callback) = &self.on_save {
            callback(tokens);
        }
        Ok(())
    }

    async fn clear(&self) -> Result<(), AuthError> {
        self.blocking(|store, account| store.delete(account).map(|_| ()))
            .await
    }

    async fn acquire_refresh_guard(
        &self,
    ) -> Result<Option<rmcp::transport::auth::CredentialRefreshGuard>, AuthError> {
        let guard = Arc::clone(&self.refresh).lock_owned().await;
        Ok(Some(rmcp::transport::auth::CredentialRefreshGuard::new(
            guard,
        )))
    }
}

/// Whether tokens are stored for a server, without reading their content.
pub fn is_logged_in(store: &dyn CredentialStore, server: &str) -> Result<bool, String> {
    let account = account_for(server)?;
    store
        .get(&account)
        .map(|tokens| tokens.is_some())
        .map_err(|err| err.to_string())
}

/// Removes a server's tokens. Returns `true` when there were some.
pub fn logout(store: &dyn CredentialStore, server: &str) -> Result<bool, String> {
    let account = account_for(server)?;
    store.delete(&account).map_err(|err| err.to_string())
}

/// What `connect` needs for an OAuth server.
pub struct OAuthSpec {
    pub server: String,
    pub url: String,
    pub client_secret: Option<String>,
}

/// Connects with the tokens that `auth login` stored.
pub struct OAuthConnector {
    spec: OAuthSpec,
    store: Arc<dyn CredentialStore>,
}

impl OAuthConnector {
    pub fn new(spec: OAuthSpec, store: Arc<dyn CredentialStore>) -> Self {
        Self { spec, store }
    }

    fn login_hint(&self) -> String {
        format!(
            "not logged in: run `toolward auth login {}`",
            self.spec.server
        )
    }
}

/// The access and refresh token of a stored login, for redaction.
fn token_values(credentials: &StoredCredentials) -> Vec<String> {
    let Ok(json) = serde_json::to_value(credentials) else {
        return Vec::new();
    };
    ["access_token", "refresh_token"]
        .iter()
        .filter_map(|key| json["token_response"][key].as_str())
        .map(str::to_owned)
        .collect()
}

fn auth_failure(err: &AuthError, secrets: &[String]) -> String {
    redact(&err.to_string(), secrets)
}

impl Connect for OAuthConnector {
    fn connect(&self, handler: UpstreamHandler) -> BoxFuture<'_, Result<RunningClient, String>> {
        Box::pin(async move {
            let account = account_for(&self.spec.server)?;
            let reread = TokenStore::new(Arc::clone(&self.store), account.clone());
            let late = handler.clone();
            let tokens = TokenStore::new(Arc::clone(&self.store), account)
                .on_save(move |values| late.add_secrets(&values));
            let stored = RmcpCredentialStore::load(&tokens)
                .await
                .map_err(|err| auth_failure(&err, &[]))?;
            let Some(stored) = stored.filter(|s| s.token_response.is_some()) else {
                return Err(self.login_hint());
            };

            let mut secrets = Vec::new();
            let client_secret = match &self.spec.client_secret {
                Some(text) => {
                    let text = text.clone();
                    let store = Arc::clone(&self.store);
                    let (value, found) = tokio::task::spawn_blocking(move || {
                        let mut found = Vec::new();
                        interpolate::expand_collecting(&text, store.as_ref(), &mut found)
                            .map(|value| (value, found))
                    })
                    .await
                    .map_err(|err| err.to_string())?
                    .map_err(|err| err.to_string())?;
                    secrets.extend(found);
                    Some(value)
                }
                None => None,
            };

            let mut manager = AuthorizationManager::new(self.spec.url.as_str())
                .await
                .map_err(|err| auth_failure(&err, &secrets))?;
            manager.set_credential_store(tokens);
            let ready = manager
                .initialize_from_store()
                .await
                .map_err(|err| auth_failure(&err, &secrets))?;
            if !ready {
                return Err(self.login_hint());
            }
            if let Some(secret) = client_secret {
                let config = OAuthClientConfig::new(stored.client_id, self.spec.url.as_str())
                    .with_client_secret(secret);
                manager
                    .configure_client(config)
                    .map_err(|err| auth_failure(&err, &secrets))?;
            }
            // Fetching the token here refreshes it when it has expired, and a
            // refresh the server rejects is reported as a login problem.
            match manager.get_access_token().await {
                Ok(token) => secrets.push(token),
                Err(AuthError::AuthorizationRequired) => {
                    return Err(format!(
                        "the login has expired: run `toolward auth login {}`",
                        self.spec.server
                    ));
                }
                Err(err) => return Err(auth_failure(&err, &secrets)),
            }
            // Both tokens, as they are after any refresh, must never reach the agent.
            let current = RmcpCredentialStore::load(&reread)
                .await
                .map_err(|err| auth_failure(&err, &secrets))?;
            if let Some(current) = current {
                secrets.extend(token_values(&current));
            }
            handler.remember_secrets(&secrets);

            let client = AuthClient::new(reqwest::Client::default(), manager);
            let config = StreamableHttpClientTransportConfig::with_uri(self.spec.url.as_str());
            let transport = StreamableHttpClientTransport::with_client(client, config);
            handler
                .serve(transport)
                .await
                .map_err(|err| redact(&format!("handshake failed: {err}"), &secrets))
        })
    }
}

/// Everything `auth login` needs to know about a server.
pub struct LoginRequest<'a> {
    pub server: &'a str,
    pub url: &'a str,
    pub oauth: &'a OAuthConfig,
}

/// Runs the browser flow and stores the tokens. `announce` receives the
/// authorization URL (it holds no secret) for users whose browser did not open.
pub async fn login(
    request: LoginRequest<'_>,
    store: Arc<dyn CredentialStore>,
    announce: &(dyn Fn(&str) + Sync),
    timeout: Duration,
) -> Result<(), String> {
    let account = account_for(request.server)?;
    let client_secret = match &request.oauth.client_secret {
        Some(text) => {
            let text = text.clone();
            let store = Arc::clone(&store);
            let value = tokio::task::spawn_blocking(move || {
                interpolate::expand_collecting(&text, store.as_ref(), &mut Vec::new())
            })
            .await
            .map_err(|err| err.to_string())?
            .map_err(|err| err.to_string())?;
            Some(value)
        }
        None => None,
    };
    let client_id = match &request.oauth.client_id {
        Some(text) => {
            let text = text.clone();
            let store = Arc::clone(&store);
            let value = tokio::task::spawn_blocking(move || {
                interpolate::expand_collecting(&text, store.as_ref(), &mut Vec::new())
            })
            .await
            .map_err(|err| err.to_string())?
            .map_err(|err| err.to_string())?;
            Some(value)
        }
        None => None,
    };
    let secrets: Vec<String> = client_secret.iter().cloned().collect();
    let fail = |err: AuthError| auth_failure(&err, &secrets);

    // Bind first: the redirect URI must be known before registration.
    let port = request.oauth.callback_port.unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|err| format!("cannot listen on 127.0.0.1:{port}: {err}"))?;
    let port = listener.local_addr().map_err(|err| err.to_string())?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let mut manager = AuthorizationManager::new(request.url).await.map_err(fail)?;
    manager.set_credential_store(TokenStore::new(store, account));
    let metadata = manager.resolve_metadata().await.map_err(fail)?.metadata;
    manager.set_metadata(metadata);

    let mut auth_request = AuthorizationRequest::new(redirect_uri)
        .with_scopes(request.oauth.scopes.clone())
        .with_client_name("toolward");
    if let Some(id) = client_id {
        auth_request = auth_request.with_preregistered_client(id);
        if let Some(secret) = client_secret.clone() {
            auth_request = auth_request.with_client_secret(secret);
        }
    }
    let session = AuthorizationSession::new(manager, auth_request)
        .await
        .map_err(|(_, err)| fail(err))?;

    let auth_url = reqwest::Url::parse(session.get_authorization_url())
        .map_err(|_| "the server gave an invalid authorization URL".to_owned())?;
    let loopback = matches!(
        auth_url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    );
    if auth_url.scheme() != "https" && !(auth_url.scheme() == "http" && loopback) {
        return Err("the server's authorization URL is not https".into());
    }
    let state = auth_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .ok_or("the authorization URL has no state")?;
    announce(auth_url.as_str());
    open_browser(auth_url.as_str());

    let callback = tokio::time::timeout(timeout, wait_for_callback(&listener, port, &state))
        .await
        .map_err(|_| format!("no authorization within {} seconds", timeout.as_secs()))??;
    session
        .handle_callback_url(&callback)
        .await
        .map_err(fail)
        .map(|_| ())
}

/// Opens the system browser. Failure is fine: the URL is printed as well.
fn open_browser(url: &str) {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(program)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Accepts connections until one carries the OAuth redirect, and returns its
/// URL. Anything else (favicon requests, port scans) is answered and ignored.
async fn wait_for_callback(
    listener: &TcpListener,
    port: u16,
    expected_state: &str,
) -> Result<String, String> {
    loop {
        let (mut stream, _) = listener.accept().await.map_err(|err| err.to_string())?;
        let Some(target) = read_request_target(&mut stream).await else {
            respond(&mut stream, "400 Bad Request", "Bad request").await;
            continue;
        };
        if !target.starts_with("/callback?") {
            respond(&mut stream, "404 Not Found", "Not found").await;
            continue;
        }
        let url = format!("http://127.0.0.1:{port}{target}");
        let parsed = reqwest::Url::parse(&url).map_err(|err| err.to_string())?;
        // Only the browser that was sent to the server knows the state.
        if !parsed
            .query_pairs()
            .any(|(key, value)| key == "state" && value == expected_state)
        {
            respond(&mut stream, "400 Bad Request", "Unexpected request").await;
            continue;
        }
        let mut error = None;
        for (key, value) in parsed.query_pairs() {
            if key == "error" {
                error = Some(value.into_owned());
            }
        }
        if let Some(code) = error {
            respond(
                &mut stream,
                "400 Bad Request",
                "Authorization failed. You can close this tab.",
            )
            .await;
            // Only the short error code is shown; descriptions are server text.
            let code: String = code
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(40)
                .collect();
            return Err(format!("the server refused the authorization ({code})"));
        }
        if !parsed.query_pairs().any(|(key, _)| key == "code") {
            respond(&mut stream, "400 Bad Request", "Missing code").await;
            continue;
        }
        respond(
            &mut stream,
            "200 OK",
            "Logged in to toolward. You can close this tab.",
        )
        .await;
        return Ok(url);
    }
}

/// The request target of a `GET` request, or `None`.
async fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = vec![0u8; 8192];
    let mut len = 0;
    let read = async {
        loop {
            let n = stream.read(&mut buffer[len..]).await.ok()?;
            if n == 0 {
                return None;
            }
            len += n;
            if buffer[..len].windows(2).any(|w| w == b"\r\n") || len == buffer.len() {
                return Some(());
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .ok()??;
    let text = String::from_utf8_lossy(&buffer[..len]);
    let line = text.lines().next()?;
    let mut parts = line.split(' ');
    (parts.next()? == "GET").then_some(())?;
    Some(parts.next()?.to_owned())
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn tokens() -> (Arc<MemoryStore>, TokenStore) {
        let memory = Arc::new(MemoryStore::new());
        let store: Arc<dyn CredentialStore> = memory.clone();
        (memory, TokenStore::new(store, "oauth.sentry".into()))
    }

    #[test]
    fn token_values_lists_both_tokens() {
        let response: rmcp::transport::auth::OAuthTokenResponse = serde_json::from_str(
            r#"{"access_token":"AT-1234","token_type":"Bearer","refresh_token":"RT-5678"}"#,
        )
        .unwrap();
        let creds = StoredCredentials::new("c".into(), Some(response), vec![], None);
        assert_eq!(token_values(&creds), ["AT-1234", "RT-5678"]);
    }

    #[test]
    fn account_names() {
        assert_eq!(account_for("sentry").unwrap(), "oauth.sentry");
        assert!(account_for("a/b").is_err());
    }

    #[tokio::test]
    async fn token_store_round_trip_and_clear() {
        let (memory, tokens) = tokens();
        assert!(RmcpCredentialStore::load(&tokens).await.unwrap().is_none());
        let creds = StoredCredentials::new("client-1".into(), None, vec!["a".into()], None);
        RmcpCredentialStore::save(&tokens, creds).await.unwrap();
        let loaded = RmcpCredentialStore::load(&tokens).await.unwrap().unwrap();
        assert_eq!(loaded.client_id, "client-1");
        assert!(memory.get("oauth.sentry").unwrap().is_some());
        RmcpCredentialStore::clear(&tokens).await.unwrap();
        assert!(memory.get("oauth.sentry").unwrap().is_none());
    }

    #[tokio::test]
    async fn unreadable_tokens_do_not_leak_into_the_error() {
        let (memory, tokens) = tokens();
        memory.set("oauth.sentry", "SECRETJUNK").unwrap();
        let err = RmcpCredentialStore::load(&tokens).await.unwrap_err();
        assert!(!err.to_string().contains("SECRETJUNK"));
    }

    #[test]
    fn login_state_and_logout() {
        let store = MemoryStore::new();
        assert!(!is_logged_in(&store, "sentry").unwrap());
        store.set("oauth.sentry", "{}").unwrap();
        assert!(is_logged_in(&store, "sentry").unwrap());
        assert!(logout(&store, "sentry").unwrap());
        assert!(!logout(&store, "sentry").unwrap());
    }

    async fn get(port: u16, target: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply
    }

    #[tokio::test]
    async fn callback_ignores_noise_and_returns_the_redirect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let waiting = tokio::spawn(async move { wait_for_callback(&listener, port, "s1").await });
        assert!(get(port, "/favicon.ico").await.contains("404"));
        assert!(get(port, "/callback?state=x").await.contains("400"));
        assert!(
            get(port, "/callback?code=c&state=wrong")
                .await
                .contains("400")
        );
        assert!(
            get(port, "/callback?code=c1&state=s1")
                .await
                .contains("200")
        );
        let url = waiting.await.unwrap().unwrap();
        assert_eq!(
            url,
            format!("http://127.0.0.1:{port}/callback?code=c1&state=s1")
        );
    }

    #[tokio::test]
    async fn callback_reports_refusal_without_server_text() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let waiting = tokio::spawn(async move { wait_for_callback(&listener, port, "s1").await });
        get(
            port,
            "/callback?state=s1&error=access_denied&error_description=EVIL%20TEXT",
        )
        .await;
        let err = waiting.await.unwrap().unwrap_err();
        assert!(err.contains("access_denied"));
        assert!(!err.contains("EVIL"));
    }

    #[tokio::test]
    async fn without_tokens_the_upstream_says_how_to_log_in() {
        use crate::upstream::Upstream;
        let spec = OAuthSpec {
            server: "sentry".into(),
            url: "http://127.0.0.1:9/mcp".into(),
            client_secret: None,
        };
        let connector = OAuthConnector::new(spec, Arc::new(MemoryStore::new()));
        let upstream = Upstream::new("sentry", Box::new(connector));
        let err = upstream.tools().await.unwrap_err();
        assert!(err.contains("toolward auth login sentry"), "{err}");
    }
}
