use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum::extract::{Json, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower_http::trace::TraceLayer;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

const CLIENT_ID: &str = "portal-desktop";
const ACCESS_TOKEN_TTL_HOURS: i64 = 24;
const REFRESH_TOKEN_TTL_DAYS: i64 = 90;
const AUTH_CODE_TTL_MINUTES: i64 = 5;

const PORTAL_ASCII_LOGO: &str = r#"                                  .             oooo
                                .o8             `888
oo.ooooo.   .ooooo.  oooo d8b .o888oo  .oooo.    888
 888' `88b d88' `88b `888""8P   888   `P  )88b   888
 888   888 888   888  888       888    .oP"888   888
 888   888 888   888  888       888 . d8(  888   888
 888bod8P' `Y8bod8P' d888b      "888" `Y888""8o o888o
 888
o888o"#;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    pending_registrations: Arc<Mutex<HashMap<String, PendingRegistration>>>,
    pending_authentications: Arc<Mutex<HashMap<String, PendingAuthentication>>>,
    public_url: String,
}

struct PendingRegistration {
    user_id: Uuid,
    username: String,
    state: PasskeyRegistration,
}

struct PendingAuthentication {
    user_id: String,
    username: String,
    query: AuthorizeQuery,
    state: PasskeyAuthentication,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct RegisterStartRequest {
    username: String,
}

#[derive(Debug, Deserialize)]
struct RegisterFinishRequest {
    flow_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
struct LoginStartRequest {
    username: String,
    oauth: AuthorizeQuery,
}

#[derive(Debug, Deserialize)]
struct LoginFinishRequest {
    flow_id: String,
    credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
struct WebauthnStartResponse {
    flow_id: String,
    public_key: Value,
}

#[derive(Debug, Serialize)]
struct LoginFinishResponse {
    redirect_uri: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    id: String,
    username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncState {
    revision: String,
    profile: Value,
    vault: Value,
}

#[derive(Debug, Deserialize)]
struct SyncPutRequest {
    expected_revision: String,
    profile: Value,
    vault: Value,
}

pub fn run(state_dir: PathBuf, bind: String, public_url: Option<String>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to start Tokio runtime")?;
    rt.block_on(run_async(state_dir, bind, public_url))
}

async fn run_async(state_dir: PathBuf, bind: String, public_url: Option<String>) -> Result<()> {
    std::fs::create_dir_all(&state_dir).context("failed to create Portal Hub state dir")?;
    let db_path = state_dir.join("hub.db");
    let db = Connection::open(db_path).context("failed to open Portal Hub database")?;
    init_db(&db)?;

    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid bind address: {}", bind))?;
    let public_url = public_url.unwrap_or_else(|| {
        if bind_addr.ip().is_loopback() {
            format!("http://portal-hub.localhost:{}", bind_addr.port())
        } else {
            format!("http://{}", bind_addr)
        }
    });
    webauthn_for_public_url(&public_url)?;
    let state = AppState {
        db: Arc::new(Mutex::new(db)),
        pending_registrations: Arc::new(Mutex::new(HashMap::new())),
        pending_authentications: Arc::new(Mutex::new(HashMap::new())),
        public_url,
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/admin", get(admin_page))
        .route("/webauthn/register/start", post(register_start))
        .route("/webauthn/register/finish", post(register_finish))
        .route("/webauthn/login/start", post(login_start))
        .route("/webauthn/login/finish", post(login_finish))
        .route("/oauth/authorize", get(authorize_page))
        .route("/oauth/token", post(token))
        .route("/api/me", get(api_me))
        .route("/api/sync", get(api_sync_get).put(api_sync_put))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", bind_addr))?;
    eprintln!("Portal Hub web listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_db(db: &Connection) -> Result<()> {
    db.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS passkeys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            passkey TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS access_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS profiles (
            user_id TEXT PRIMARY KEY,
            revision TEXT NOT NULL,
            profile TEXT NOT NULL,
            vault TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            user_id TEXT,
            detail TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

async fn root(State(state): State<AppState>) -> Response {
    if user_count(&state).unwrap_or(0) == 0 {
        Redirect::to("/admin").into_response()
    } else {
        Html(page(
            "Portal Hub",
            &format!(
                r#"<section class="panel">
                    <p class="eyebrow">Hub online</p>
                    <h1>Portal Hub is running.</h1>
                    <p class="lead">Desktop clients can authenticate with passkeys and sync through <code>{}</code>.</p>
                  </section>"#,
                html_escape(&state.public_url)
            ),
        ))
        .into_response()
    }
}

async fn admin_page(State(state): State<AppState>) -> Response {
    if user_count(&state).unwrap_or(0) > 0 {
        return Html(page(
            "Portal Hub",
            r#"<section class="panel">
                <p class="eyebrow">Owner exists</p>
                <h1>Portal Hub is ready.</h1>
                <p class="lead">Continue through Portal desktop sign-in to authenticate with your passkey.</p>
              </section>"#,
        ))
        .into_response();
    }

    Html(page(
        "Create Portal Hub Owner",
        r#"<section class="panel setup-panel">
            <div class="steps" aria-label="Setup progress">
              <span class="step-dot active" data-step-dot="1">1</span>
              <span class="step-line"></span>
              <span class="step-dot" data-step-dot="2">2</span>
            </div>
            <div id="setup-error" class="error" hidden></div>
            <form id="owner-form" class="flow" autocomplete="off">
              <div class="wizard-step" data-step="1">
                <p class="eyebrow">First owner</p>
                <h1>Name this account.</h1>
                <p class="lead">This name is stored on the Hub and shown in Portal after sign-in.</p>
                <label>Account name<input id="username" name="username" autocomplete="username webauthn" required minlength="2" maxlength="64" autofocus></label>
                <button type="button" id="next-button">Next</button>
              </div>
              <div class="wizard-step" data-step="2" hidden>
                <p class="eyebrow">Passkey</p>
                <h1>Create a passkey.</h1>
                <p class="lead">Portal Hub does not store passwords. Your browser or 1Password will prompt you to create the passkey.</p>
                <div class="passkey-callout">
                  <span class="passkey-icon" aria-hidden="true"></span>
                  <div>
                    <strong>Use this device, a security key, or your phone.</strong>
                    <p>The QR or cross-device prompt is controlled by your browser and passkey provider.</p>
                  </div>
                </div>
                <div class="actions">
                  <button type="button" class="secondary" id="back-button">Back</button>
                  <button type="submit" id="create-button">Create passkey</button>
                </div>
              </div>
            </form>
          </section>"#,
    ))
    .into_response()
}

async fn authorize_page(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    if user_count(&state).unwrap_or(0) == 0 {
        return Redirect::to("/admin").into_response();
    }
    if let Err(error) = validate_authorize_query(&query) {
        return (
            StatusCode::BAD_REQUEST,
            Html(page("Invalid Request", &error_panel(&error.to_string()))),
        )
            .into_response();
    }

    Html(page(
        "Sign In To Portal Hub",
        r#"<section class="panel auth-panel">
            <p class="eyebrow">Portal desktop sign-in</p>
            <h1>Use your passkey.</h1>
            <p class="lead">Portal Hub will confirm your passkey, then return you to Portal.</p>
            <div id="login-error" class="error" hidden></div>
            <form id="login-form" class="flow" autocomplete="on">
              <label>Account name<input id="username" name="username" autocomplete="username webauthn" required autofocus></label>
              <button type="submit" id="login-button">Sign in with passkey</button>
            </form>
            <div class="passkey-callout compact">
              <span class="passkey-icon" aria-hidden="true"></span>
              <p>1Password, your browser, or your operating system may offer a QR code for another device.</p>
            </div>
          </section>"#,
    ))
    .into_response()
}

async fn register_start(
    State(state): State<AppState>,
    Json(request): Json<RegisterStartRequest>,
) -> Response {
    match register_start_inner(&state, request) {
        Ok(response) => Json(response).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

fn register_start_inner(
    state: &AppState,
    request: RegisterStartRequest,
) -> Result<WebauthnStartResponse> {
    if user_count(state)? > 0 {
        bail!("owner account already exists");
    }
    validate_username(&request.username)?;
    let username = request.username.trim().to_string();
    let user_id = Uuid::new_v4();
    let webauthn = webauthn(state)?;
    let (challenge, registration_state) =
        webauthn.start_passkey_registration(user_id, &username, &username, None)?;
    let flow_id = random_token();
    state
        .pending_registrations
        .lock()
        .map_err(|_| anyhow!("registration lock poisoned"))?
        .insert(
            flow_id.clone(),
            PendingRegistration {
                user_id,
                username,
                state: registration_state,
            },
        );
    let mut public_key = serde_json::to_value(challenge)?;
    apply_passkey_client_preferences(&mut public_key, true);
    Ok(WebauthnStartResponse {
        flow_id,
        public_key,
    })
}

async fn register_finish(
    State(state): State<AppState>,
    Json(request): Json<RegisterFinishRequest>,
) -> Response {
    match register_finish_inner(&state, request) {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

fn register_finish_inner(state: &AppState, request: RegisterFinishRequest) -> Result<()> {
    if user_count(state)? > 0 {
        bail!("owner account already exists");
    }
    let pending = state
        .pending_registrations
        .lock()
        .map_err(|_| anyhow!("registration lock poisoned"))?
        .remove(&request.flow_id)
        .ok_or_else(|| anyhow!("registration flow expired"))?;
    let passkey =
        webauthn(state)?.finish_passkey_registration(&request.credential, &pending.state)?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    ensure_credential_is_unique(&db, &passkey)?;
    insert_user(&db, pending.user_id, &pending.username)?;
    insert_passkey(&db, pending.user_id, &passkey)?;
    audit_db(
        &db,
        "owner_created",
        Some(&pending.user_id.to_string()),
        json!({"username": pending.username, "auth_method": "passkey"}),
    )?;
    Ok(())
}

async fn login_start(
    State(state): State<AppState>,
    Json(request): Json<LoginStartRequest>,
) -> Response {
    match login_start_inner(&state, request) {
        Ok(response) => Json(response).into_response(),
        Err(error) => json_error(StatusCode::UNAUTHORIZED, error),
    }
}

fn login_start_inner(
    state: &AppState,
    request: LoginStartRequest,
) -> Result<WebauthnStartResponse> {
    validate_authorize_query(&request.oauth)?;
    validate_username(&request.username)?;
    let username = request.username.trim().to_string();
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let Some(user_id) = db
        .query_row(
            "SELECT id FROM users WHERE username = ?1",
            [username.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    else {
        audit_db(
            &db,
            "login_failed",
            None,
            json!({"username": username, "reason": "unknown_user"}),
        )?;
        bail!("unknown account");
    };
    let passkeys = load_passkeys_for_user(&db, &user_id)?;
    if passkeys.is_empty() {
        audit_db(
            &db,
            "login_failed",
            Some(&user_id),
            json!({"username": username, "reason": "no_passkeys"}),
        )?;
        bail!("this account has no passkeys");
    }
    drop(db);

    let webauthn = webauthn(state)?;
    let passkey_values: Vec<Passkey> = passkeys.into_iter().map(|(_, passkey)| passkey).collect();
    let (challenge, auth_state) = webauthn.start_passkey_authentication(&passkey_values)?;
    let flow_id = random_token();
    state
        .pending_authentications
        .lock()
        .map_err(|_| anyhow!("authentication lock poisoned"))?
        .insert(
            flow_id.clone(),
            PendingAuthentication {
                user_id,
                username,
                query: request.oauth,
                state: auth_state,
            },
        );
    let mut public_key = serde_json::to_value(challenge)?;
    apply_passkey_client_preferences(&mut public_key, false);
    Ok(WebauthnStartResponse {
        flow_id,
        public_key,
    })
}

async fn login_finish(
    State(state): State<AppState>,
    Json(request): Json<LoginFinishRequest>,
) -> Response {
    match login_finish_inner(&state, request) {
        Ok(response) => Json(response).into_response(),
        Err(error) => json_error(StatusCode::UNAUTHORIZED, error),
    }
}

fn login_finish_inner(
    state: &AppState,
    request: LoginFinishRequest,
) -> Result<LoginFinishResponse> {
    let pending = state
        .pending_authentications
        .lock()
        .map_err(|_| anyhow!("authentication lock poisoned"))?
        .remove(&request.flow_id)
        .ok_or_else(|| anyhow!("authentication flow expired"))?;
    let auth_result =
        webauthn(state)?.finish_passkey_authentication(&request.credential, &pending.state)?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let mut passkeys = load_passkeys_for_user(&db, &pending.user_id)?;
    let mut matched_passkey_id = None;
    for (passkey_id, passkey) in passkeys.iter_mut() {
        if passkey.cred_id() == auth_result.cred_id() {
            if auth_result.needs_update() {
                passkey.update_credential(&auth_result);
                update_passkey(&db, passkey_id, passkey)?;
            }
            matched_passkey_id = Some(passkey_id.clone());
            break;
        }
    }
    let Some(passkey_id) = matched_passkey_id else {
        audit_db(
            &db,
            "login_failed",
            Some(&pending.user_id),
            json!({"username": pending.username, "reason": "credential_not_found"}),
        )?;
        bail!("passkey is not registered to this account");
    };
    db.execute(
        "UPDATE passkeys SET last_used_at = ?1 WHERE id = ?2",
        params![Utc::now().to_rfc3339(), passkey_id],
    )?;

    let code = random_token();
    let expires_at = (Utc::now() + ChronoDuration::minutes(AUTH_CODE_TTL_MINUTES)).to_rfc3339();
    db.execute(
        "INSERT INTO auth_codes (code, user_id, client_id, redirect_uri, code_challenge, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            code,
            pending.user_id,
            pending.query.client_id,
            pending.query.redirect_uri,
            pending.query.code_challenge,
            expires_at
        ],
    )?;
    audit_db(
        &db,
        "login_success",
        Some(&pending.user_id),
        json!({"client_id": pending.query.client_id, "auth_method": "passkey"}),
    )?;

    Ok(LoginFinishResponse {
        redirect_uri: format!(
            "{}?code={}&state={}",
            pending.query.redirect_uri,
            urlencoding::encode(&code),
            urlencoding::encode(&pending.query.state)
        ),
    })
}

async fn token(
    State(state): State<AppState>,
    axum::Form(request): axum::Form<TokenRequest>,
) -> Response {
    match token_inner(&state, request) {
        Ok(response) => Json(response).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

fn token_inner(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(state, request),
        "refresh_token" => exchange_refresh_token(state, request),
        _ => bail!("unsupported grant_type"),
    }
}

fn exchange_authorization_code(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    let code = request.code.ok_or_else(|| anyhow!("missing code"))?;
    let verifier = request
        .code_verifier
        .ok_or_else(|| anyhow!("missing code_verifier"))?;
    let redirect_uri = request
        .redirect_uri
        .ok_or_else(|| anyhow!("missing redirect_uri"))?;
    let client_id = request
        .client_id
        .ok_or_else(|| anyhow!("missing client_id"))?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let Some((user_id, stored_client_id, stored_redirect_uri, challenge, expires_at)) = db
        .query_row(
            "SELECT user_id, client_id, redirect_uri, code_challenge, expires_at FROM auth_codes WHERE code = ?1",
            [&code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    else {
        bail!("invalid code");
    };
    if stored_client_id != client_id || stored_redirect_uri != redirect_uri {
        bail!("invalid code binding");
    }
    if DateTime::parse_from_rfc3339(&expires_at)?.with_timezone(&Utc) < Utc::now() {
        bail!("authorization code expired");
    }
    if pkce_challenge(&verifier) != challenge {
        bail!("invalid code_verifier");
    }
    db.execute("DELETE FROM auth_codes WHERE code = ?1", [&code])?;
    issue_tokens(&db, &user_id)
}

fn exchange_refresh_token(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    let refresh_token = request
        .refresh_token
        .ok_or_else(|| anyhow!("missing refresh_token"))?;
    let refresh_hash = token_hash(&refresh_token);
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let Some((user_id, expires_at)) = db
        .query_row(
            "SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?1",
            [&refresh_hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    else {
        bail!("invalid refresh_token");
    };
    if DateTime::parse_from_rfc3339(&expires_at)?.with_timezone(&Utc) < Utc::now() {
        bail!("refresh_token expired");
    }
    db.execute(
        "DELETE FROM refresh_tokens WHERE token_hash = ?1",
        [&refresh_hash],
    )?;
    issue_tokens(&db, &user_id)
}

async fn api_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authenticated_user(&state, &headers) {
        Ok((id, username)) => Json(MeResponse { id, username }).into_response(),
        Err(response) => response,
    }
}

async fn api_sync_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match load_profile(&state, &user_id) {
        Ok(profile) => Json(json!({
            "api_version": 1,
            "generated_at": Utc::now(),
            "revision": profile.revision,
            "profile": profile.profile,
            "vault": profile.vault,
        }))
        .into_response(),
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_sync_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncPutRequest>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match save_profile(&state, &user_id, request) {
        Ok(profile) => Json(json!({
            "api_version": 1,
            "generated_at": Utc::now(),
            "revision": profile.revision,
            "profile": profile.profile,
            "vault": profile.vault,
        }))
        .into_response(),
        Err(error) if error.to_string().contains("revision conflict") => {
            json_error(StatusCode::CONFLICT, error)
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

fn authenticated_user(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<(String, String), Response> {
    let Some(header) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing bearer token"})),
        )
            .into_response());
    };
    let Ok(value) = header.to_str() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid authorization header"})),
        )
            .into_response());
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid authorization scheme"})),
        )
            .into_response());
    };
    let hash = token_hash(token);
    let db = state.db.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "database lock failed"})),
        )
            .into_response()
    })?;
    let row = db
        .query_row(
            "SELECT users.id, users.username, access_tokens.expires_at FROM access_tokens JOIN users ON users.id = access_tokens.user_id WHERE access_tokens.token_hash = ?1",
            [&hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "token lookup failed"}))).into_response())?;
    let Some((user_id, username, expires_at)) = row else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid bearer token"})),
        )
            .into_response());
    };
    if DateTime::parse_from_rfc3339(&expires_at)
        .map(|date| date.with_timezone(&Utc) < Utc::now())
        .unwrap_or(true)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "expired bearer token"})),
        )
            .into_response());
    }
    Ok((user_id, username))
}

fn load_profile(state: &AppState, user_id: &str) -> Result<SyncState> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let row = db
        .query_row(
            "SELECT revision, profile, vault FROM profiles WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((revision, profile, vault)) = row {
        return Ok(SyncState {
            revision,
            profile: serde_json::from_str(&profile)?,
            vault: serde_json::from_str(&vault)?,
        });
    }
    Ok(SyncState {
        revision: "0".to_string(),
        profile: json!({"hosts": {"hosts": [], "groups": []}, "settings": {}, "snippets": {"snippets": []}}),
        vault: json!({"keys": []}),
    })
}

fn save_profile(state: &AppState, user_id: &str, request: SyncPutRequest) -> Result<SyncState> {
    let current = load_profile(state, user_id)?;
    if current.revision != request.expected_revision {
        bail!(
            "revision conflict: expected {}, current {}",
            request.expected_revision,
            current.revision
        );
    }
    let next = SyncState {
        revision: Uuid::new_v4().to_string(),
        profile: request.profile,
        vault: request.vault,
    };
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    db.execute(
        "INSERT INTO profiles (user_id, revision, profile, vault, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET revision = excluded.revision, profile = excluded.profile, vault = excluded.vault, updated_at = excluded.updated_at",
        params![
            user_id,
            next.revision,
            serde_json::to_string(&next.profile)?,
            serde_json::to_string(&next.vault)?,
            Utc::now().to_rfc3339()
        ],
    )?;
    audit_db(
        &db,
        "sync_put",
        Some(user_id),
        json!({"revision": next.revision, "vault_key_count": vault_key_count(&next.vault)}),
    )?;
    Ok(next)
}

fn issue_tokens(db: &Connection, user_id: &str) -> Result<TokenResponse> {
    let access_token = random_token();
    let refresh_token = random_token();
    let now = Utc::now();
    let access_expires = now + ChronoDuration::hours(ACCESS_TOKEN_TTL_HOURS);
    let refresh_expires = now + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS);
    db.execute(
        "INSERT INTO access_tokens (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash(&access_token), user_id, access_expires.to_rfc3339(), now.to_rfc3339()],
    )?;
    db.execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash(&refresh_token), user_id, refresh_expires.to_rfc3339(), now.to_rfc3339()],
    )?;
    audit_db(
        db,
        "token_issued",
        Some(user_id),
        json!({"client_id": CLIENT_ID}),
    )?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_HOURS * 3600,
        refresh_token,
    })
}

fn user_count(state: &AppState) -> Result<i64> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    Ok(db.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?)
}

fn validate_authorize_query(query: &AuthorizeQuery) -> Result<()> {
    if query.response_type != "code" {
        bail!("unsupported response_type");
    }
    if query.client_id != CLIENT_ID {
        bail!("unknown client_id");
    }
    if query.code_challenge_method != "S256" {
        bail!("unsupported code_challenge_method");
    }
    if query.code_challenge.len() < 32 || query.state.len() < 16 {
        bail!("invalid OAuth request");
    }
    let redirect = Url::parse(&query.redirect_uri)?;
    if redirect.scheme() != "http" {
        bail!("redirect_uri must use loopback http");
    }
    let host = redirect.host_str().unwrap_or_default();
    if host != "127.0.0.1" && host != "localhost" && host != "::1" {
        bail!("redirect_uri must be loopback");
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<()> {
    let username = username.trim();
    if username.len() < 2 || username.len() > 64 {
        bail!("account name must be 2-64 characters");
    }
    if !username
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        bail!("account name may only contain letters, numbers, dots, dashes, underscores, and @");
    }
    Ok(())
}

fn apply_passkey_client_preferences(public_key: &mut Value, is_registration: bool) {
    let Some(options) = public_key
        .get_mut("publicKey")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    options.insert(
        "hints".to_string(),
        json!(["client-device", "security-key"]),
    );
    if is_registration {
        let authenticator_selection = options
            .entry("authenticatorSelection")
            .or_insert_with(|| json!({}));
        if let Some(selection) = authenticator_selection.as_object_mut() {
            selection.insert("residentKey".to_string(), json!("preferred"));
            selection.insert("requireResidentKey".to_string(), json!(false));
        }
    }
}

fn webauthn(state: &AppState) -> Result<Webauthn> {
    webauthn_for_public_url(&state.public_url)
}

fn webauthn_for_public_url(public_url: &str) -> Result<Webauthn> {
    let origin = Url::parse(public_url.trim_end_matches('/'))?;
    let host = origin
        .host_str()
        .ok_or_else(|| anyhow!("Portal Hub public URL must include a host"))?;
    if origin.scheme() != "https" && !is_local_passkey_host(host) {
        bail!("passkeys require https, except localhost development domains");
    }
    let builder = WebauthnBuilder::new(host, &origin)?
        .rp_name("Portal Hub")
        .allow_any_port(true);
    Ok(builder.build()?)
}

fn is_local_passkey_host(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

fn insert_user(db: &Connection, user_id: Uuid, username: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    if legacy_user_auth_columns(db)? {
        db.execute(
            "INSERT INTO users (id, username, password_hash, totp_secret, created_at) VALUES (?1, ?2, '', '', ?3)",
            params![user_id.to_string(), username.trim(), now],
        )?;
    } else {
        db.execute(
            "INSERT INTO users (id, username, created_at) VALUES (?1, ?2, ?3)",
            params![user_id.to_string(), username.trim(), now],
        )?;
    }
    Ok(())
}

fn legacy_user_auth_columns(db: &Connection) -> Result<bool> {
    let mut statement = db.prepare("PRAGMA table_info(users)")?;
    let mut rows = statement.query([])?;
    let mut has_password_hash = false;
    let mut has_totp_secret = false;
    while let Some(row) = rows.next()? {
        let column_name: String = row.get(1)?;
        has_password_hash |= column_name == "password_hash";
        has_totp_secret |= column_name == "totp_secret";
    }
    Ok(has_password_hash && has_totp_secret)
}

fn insert_passkey(db: &Connection, user_id: Uuid, passkey: &Passkey) -> Result<()> {
    db.execute(
        "INSERT INTO passkeys (id, user_id, passkey, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            Uuid::new_v4().to_string(),
            user_id.to_string(),
            serde_json::to_string(passkey)?,
            Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}

fn update_passkey(db: &Connection, passkey_id: &str, passkey: &Passkey) -> Result<()> {
    db.execute(
        "UPDATE passkeys SET passkey = ?1 WHERE id = ?2",
        params![serde_json::to_string(passkey)?, passkey_id],
    )?;
    Ok(())
}

fn load_passkeys_for_user(db: &Connection, user_id: &str) -> Result<Vec<(String, Passkey)>> {
    let mut statement = db.prepare("SELECT id, passkey FROM passkeys WHERE user_id = ?1")?;
    let rows = statement.query_map([user_id], |row| {
        let id: String = row.get(0)?;
        let passkey_json: String = row.get(1)?;
        Ok((id, passkey_json))
    })?;
    let mut passkeys = Vec::new();
    for row in rows {
        let (id, passkey_json) = row?;
        passkeys.push((id, serde_json::from_str(&passkey_json)?));
    }
    Ok(passkeys)
}

fn ensure_credential_is_unique(db: &Connection, passkey: &Passkey) -> Result<()> {
    let mut statement = db.prepare("SELECT passkey FROM passkeys")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    for row in rows {
        let existing: Passkey = serde_json::from_str(&row?)?;
        if existing.cred_id() == passkey.cred_id() {
            bail!("this passkey is already registered");
        }
    }
    Ok(())
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn token_hash(token: &str) -> String {
    hex_lower(&Sha256::digest(token.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn audit_db(db: &Connection, event: &str, user_id: Option<&str>, detail: Value) -> Result<()> {
    db.execute(
        "INSERT INTO audit_events (timestamp, event, user_id, detail) VALUES (?1, ?2, ?3, ?4)",
        params![
            Utc::now().to_rfc3339(),
            event,
            user_id,
            serde_json::to_string(&detail)?
        ],
    )?;
    Ok(())
}

fn vault_key_count(vault: &Value) -> usize {
    vault
        .get("keys")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn json_error(status: StatusCode, error: anyhow::Error) -> Response {
    (status, Json(json!({"error": error.to_string()}))).into_response()
}

fn error_panel(error: &str) -> String {
    format!(
        r#"<section class="panel"><p class="eyebrow">Request failed</p><h1>Something needs attention.</h1><p class="lead">{}</p></section>"#,
        html_escape(error)
    )
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{title}</title>
          <style>
            :root {{
              color-scheme: dark;
              --bg: #090b10;
              --surface: #121720;
              --surface-2: #171d28;
              --line: #2a3444;
              --line-strong: #4b5b70;
              --text: #edf2f7;
              --muted: #aab7c8;
              --soft: #7f8da3;
              --accent: #63d2ff;
              --accent-2: #9be564;
              --danger: #ff8f8f;
              --shadow: rgba(0, 0, 0, 0.45);
            }}
            * {{ box-sizing: border-box; }}
            body {{
              margin: 0;
              min-height: 100vh;
              background:
                radial-gradient(circle at top left, rgba(99, 210, 255, 0.11), transparent 34rem),
                linear-gradient(145deg, #080a0f 0%, #0d1118 48%, #101620 100%);
              color: var(--text);
              font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }}
            body::before {{
              content: "";
              position: fixed;
              inset: 0;
              pointer-events: none;
              background-image: linear-gradient(rgba(255,255,255,0.035) 1px, transparent 1px);
              background-size: 100% 4px;
              opacity: 0.18;
            }}
            main {{
              width: min(1120px, calc(100vw - 32px));
              min-height: 100vh;
              margin: 0 auto;
              display: grid;
              grid-template-columns: minmax(0, 1fr) minmax(360px, 480px);
              align-items: center;
              gap: clamp(28px, 6vw, 88px);
              padding: 56px 0;
              position: relative;
            }}
            .brand {{
              min-width: 0;
            }}
            .logo {{
              margin: 0;
              color: #c7f4ff;
              font: 700 clamp(7px, 0.92vw, 12px) / 1.05 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
              white-space: pre;
              text-shadow: 0 0 26px rgba(99, 210, 255, 0.22);
            }}
            .brand-copy {{
              max-width: 520px;
              margin-top: 34px;
              color: var(--muted);
              font-size: 17px;
              line-height: 1.65;
            }}
            .shell-label {{
              display: inline-flex;
              align-items: center;
              gap: 8px;
              margin-bottom: 28px;
              color: var(--accent-2);
              font: 700 12px / 1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
              letter-spacing: 0;
            }}
            .shell-label::before {{
              content: "";
              width: 8px;
              height: 8px;
              border-radius: 50%;
              background: var(--accent-2);
              box-shadow: 0 0 16px rgba(155, 229, 100, 0.7);
            }}
            .panel {{
              width: 100%;
              border: 1px solid var(--line);
              background: rgba(18, 23, 32, 0.88);
              box-shadow: 0 24px 80px var(--shadow);
              border-radius: 8px;
              padding: clamp(26px, 4vw, 38px);
              backdrop-filter: blur(18px);
            }}
            .eyebrow {{
              margin: 0 0 14px;
              color: var(--accent);
              font: 700 12px / 1.3 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            }}
            h1 {{
              margin: 0;
              font-size: clamp(31px, 4.4vw, 48px);
              line-height: 1.04;
              letter-spacing: 0;
            }}
            .lead {{
              margin: 18px 0 0;
              color: var(--muted);
              font-size: 16px;
              line-height: 1.55;
            }}
            label {{
              display: block;
              margin-top: 28px;
              color: var(--muted);
              font-weight: 700;
              font-size: 13px;
            }}
            input {{
              width: 100%;
              margin-top: 9px;
              padding: 14px 14px;
              border: 1px solid var(--line-strong);
              border-radius: 7px;
              background: #0b1017;
              color: var(--text);
              font: inherit;
              outline: none;
            }}
            input:focus {{
              border-color: var(--accent);
              box-shadow: 0 0 0 3px rgba(99, 210, 255, 0.14);
            }}
            button {{
              width: 100%;
              margin-top: 22px;
              min-height: 48px;
              border: 1px solid rgba(99, 210, 255, 0.4);
              border-radius: 7px;
              background: var(--accent);
              color: #061017;
              font: 800 15px / 1 system-ui, sans-serif;
              cursor: pointer;
            }}
            button:hover {{ filter: brightness(1.04); }}
            button:disabled {{ opacity: 0.58; cursor: wait; }}
            button.secondary {{
              background: transparent;
              border-color: var(--line-strong);
              color: var(--text);
            }}
            .actions {{
              display: grid;
              grid-template-columns: 1fr 1fr;
              gap: 12px;
              margin-top: 6px;
            }}
            .actions button {{ margin-top: 16px; }}
            .steps {{
              display: flex;
              align-items: center;
              gap: 12px;
              margin-bottom: 28px;
            }}
            .step-dot {{
              display: grid;
              place-items: center;
              width: 30px;
              height: 30px;
              border: 1px solid var(--line-strong);
              border-radius: 50%;
              color: var(--soft);
              font: 800 12px / 1 ui-monospace, monospace;
            }}
            .step-dot.active {{
              border-color: var(--accent);
              color: var(--accent);
              box-shadow: 0 0 0 3px rgba(99, 210, 255, 0.11);
            }}
            .step-line {{
              height: 1px;
              flex: 1;
              background: var(--line);
            }}
            .passkey-callout {{
              display: grid;
              grid-template-columns: 42px 1fr;
              gap: 14px;
              align-items: start;
              margin-top: 24px;
              padding: 16px;
              border: 1px solid var(--line);
              border-radius: 8px;
              background: var(--surface-2);
              color: var(--muted);
            }}
            .passkey-callout strong {{
              display: block;
              color: var(--text);
              margin-bottom: 5px;
            }}
            .passkey-callout p {{ margin: 0; line-height: 1.45; }}
            .passkey-callout.compact {{
              grid-template-columns: 32px 1fr;
              font-size: 14px;
            }}
            .passkey-icon {{
              width: 42px;
              height: 42px;
              border-radius: 8px;
              border: 1px solid rgba(155, 229, 100, 0.35);
              background:
                linear-gradient(135deg, rgba(155, 229, 100, 0.2), rgba(99, 210, 255, 0.08)),
                #0c1219;
              position: relative;
            }}
            .passkey-icon::before {{
              content: "";
              position: absolute;
              left: 13px;
              top: 9px;
              width: 16px;
              height: 16px;
              border: 2px solid var(--accent-2);
              border-radius: 50%;
            }}
            .passkey-icon::after {{
              content: "";
              position: absolute;
              left: 20px;
              top: 24px;
              width: 2px;
              height: 11px;
              background: var(--accent-2);
              box-shadow: 6px 5px 0 var(--accent-2), 11px 1px 0 var(--accent-2);
            }}
            .error {{
              margin-bottom: 18px;
              padding: 12px 14px;
              border: 1px solid rgba(255, 143, 143, 0.38);
              border-radius: 7px;
              background: rgba(255, 143, 143, 0.08);
              color: var(--danger);
            }}
            code {{
              color: var(--accent-2);
              word-break: break-all;
            }}
            @media (max-width: 840px) {{
              main {{
                grid-template-columns: 1fr;
                align-items: start;
                padding: 32px 0;
              }}
              .brand-copy {{ margin-top: 20px; }}
              .panel {{ padding: 24px; }}
            }}
            @media (max-width: 480px) {{
              main {{ width: min(100vw - 24px, 1120px); }}
              .actions {{ grid-template-columns: 1fr; }}
              .logo {{ font-size: 6px; }}
            }}
          </style>
        </head>
        <body>
          <main>
            <section class="brand" aria-label="Portal Hub">
              <div class="shell-label">PORTAL HUB</div>
              <pre class="logo">{}</pre>
              <p class="brand-copy">A private command center for persistent sessions, synced SSH profiles, and encrypted key material.</p>
            </section>
            {}
          </main>
          <script>
            {}
          </script>
        </body>
        </html>"#,
        html_escape(PORTAL_ASCII_LOGO),
        body,
        passkey_script()
    )
}

fn passkey_script() -> &'static str {
    r#"
      function showError(id, message) {
        const node = document.getElementById(id);
        if (!node) return;
        node.textContent = message;
        node.hidden = false;
      }
      function clearError(id) {
        const node = document.getElementById(id);
        if (!node) return;
        node.textContent = "";
        node.hidden = true;
      }
      function b64urlToBuffer(value) {
        const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
      }
      function bufferToB64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      }
      function creationOptionsFromJSON(options) {
        options = options.publicKey || options;
        options.challenge = b64urlToBuffer(options.challenge);
        options.user.id = b64urlToBuffer(options.user.id);
        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map((credential) => ({
            ...credential,
            id: b64urlToBuffer(credential.id),
          }));
        }
        return options;
      }
      function requestOptionsFromJSON(options) {
        options = options.publicKey || options;
        options.challenge = b64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map((credential) => ({
            ...credential,
            id: b64urlToBuffer(credential.id),
          }));
        }
        return options;
      }
      function credentialToJSON(credential) {
        const response = credential.response;
        const json = {
          id: credential.id,
          rawId: bufferToB64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: bufferToB64url(response.clientDataJSON),
          },
        };
        if (response.attestationObject) json.response.attestationObject = bufferToB64url(response.attestationObject);
        if (response.authenticatorData) json.response.authenticatorData = bufferToB64url(response.authenticatorData);
        if (response.signature) json.response.signature = bufferToB64url(response.signature);
        if (response.userHandle) json.response.userHandle = bufferToB64url(response.userHandle);
        if (typeof response.getTransports === "function") json.response.transports = response.getTransports();
        if (credential.getClientExtensionResults) json.extensions = credential.getClientExtensionResults();
        return json;
      }
      async function postJSON(url, body) {
        const response = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        const json = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(json.error || "Request failed");
        return json;
      }
      function setSetupStep(step) {
        document.querySelectorAll("[data-step]").forEach((node) => {
          node.hidden = node.dataset.step !== String(step);
        });
        document.querySelectorAll("[data-step-dot]").forEach((node) => {
          node.classList.toggle("active", node.dataset.stepDot === String(step));
        });
      }
      function initOwnerWizard() {
        const form = document.getElementById("owner-form");
        const username = document.getElementById("username");
        const next = document.getElementById("next-button");
        const back = document.getElementById("back-button");
        const submit = document.getElementById("create-button");
        if (!form || !username || !next || !back || !submit) return;
        next.addEventListener("click", () => {
          clearError("setup-error");
          if (!username.reportValidity()) return;
          setSetupStep(2);
          submit.focus();
        });
        back.addEventListener("click", () => {
          clearError("setup-error");
          setSetupStep(1);
          username.focus();
        });
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          clearError("setup-error");
          submit.disabled = true;
          submit.textContent = "Waiting for passkey...";
          try {
            const start = await postJSON("/webauthn/register/start", { username: username.value });
            const credential = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(start.public_key) });
            await postJSON("/webauthn/register/finish", {
              flow_id: start.flow_id,
              credential: credentialToJSON(credential),
            });
            document.querySelector(".setup-panel").innerHTML =
              '<p class="eyebrow">Owner created</p><h1>Passkey enrolled.</h1><p class="lead">Return to Portal and sign in to Portal Hub.</p>';
          } catch (error) {
            showError("setup-error", error.message || String(error));
          } finally {
            submit.disabled = false;
            submit.textContent = "Create passkey";
          }
        });
      }
      function initPasskeyLogin() {
        const form = document.getElementById("login-form");
        const username = document.getElementById("username");
        const submit = document.getElementById("login-button");
        if (!form || !username || !submit) return;
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          clearError("login-error");
          submit.disabled = true;
          submit.textContent = "Waiting for passkey...";
          try {
            const oauth = Object.fromEntries(new URLSearchParams(window.location.search).entries());
            const start = await postJSON("/webauthn/login/start", { username: username.value, oauth });
            const credential = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(start.public_key) });
            const finish = await postJSON("/webauthn/login/finish", {
              flow_id: start.flow_id,
              credential: credentialToJSON(credential),
            });
            window.location.assign(finish.redirect_uri);
          } catch (error) {
            showError("login-error", error.message || String(error));
          } finally {
            submit.disabled = false;
            submit.textContent = "Sign in with passkey";
          }
        });
      }
      if (document.getElementById("owner-form")) {
        initOwnerWizard();
      }
      if (document.getElementById("login-form")) {
        initPasskeyLogin();
      }
    "#
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
