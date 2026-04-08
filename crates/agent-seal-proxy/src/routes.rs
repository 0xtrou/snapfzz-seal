use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use bytes::Bytes;
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::info;

use agent_seal_core::error::SealError;

use crate::{
    auth::{VirtualKeyAuth, admin_auth_middleware},
    provider::{provider_endpoint, provider_for_model, proxy_request},
    rate_limit::RateLimitLayer,
    state::{ProxyState, VirtualKey},
    stream::stream_response,
};

#[derive(Clone)]
pub struct AppState {
    pub proxy: ProxyState,
    pub rate_limit: RateLimitLayer,
}

impl axum::extract::FromRef<AppState> for ProxyState {
    fn from_ref(state: &AppState) -> Self {
        state.proxy.clone()
    }
}

impl axum::extract::FromRef<AppState> for RateLimitLayer {
    fn from_ref(state: &AppState) -> Self {
        state.rate_limit.clone()
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub sandbox_id: Option<String>,
    pub ttl_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct KeyListItem {
    pub id: String,
    pub key_prefix: String,
    pub sandbox_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

pub fn build_router(state: AppState) -> Result<Router, SealError> {
    let admin_token = resolve_admin_token(std::env::var("AGENT_SEAL_ADMIN_TOKEN").ok())?;
    Ok(build_router_with_admin_token(state, admin_token))
}

pub(crate) fn build_router_with_admin_token(state: AppState, admin_token: String) -> Router {
    let admin_routes = Router::new()
        .route("/admin/keys", post(create_key).get(list_keys))
        .route("/admin/keys/{key_id}", delete(revoke_key))
        .route_layer(middleware::from_fn_with_state(
            admin_token,
            admin_auth_middleware,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/_test/authenticated", get(authenticated_probe))
        .route("/v1/chat/completions", post(chat_completions))
        .merge(admin_routes)
        .with_state(state)
}

pub(crate) fn resolve_admin_token(admin_token: Option<String>) -> Result<String, SealError> {
    admin_token.ok_or_else(|| {
        SealError::InvalidInput("AGENT_SEAL_ADMIN_TOKEN env var is required".to_string())
    })
}

async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok"}))
}

async fn authenticated_probe(_auth: VirtualKeyAuth) -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status":"authorized"})))
}

async fn create_key(
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    let now = unix_ts_secs();
    let id = format!("vk_{}", random_string(16));
    let key = format!("as-{}", random_string(32));

    let record = VirtualKey::new(
        id.clone(),
        &key,
        req.sandbox_id,
        now,
        now.saturating_add(req.ttl_secs),
    );

    state.proxy.add_key(record).await;
    state
        .rate_limit
        .cleanup_stale_limiters(Duration::from_secs(10 * 60))
        .await;
    (StatusCode::CREATED, Json(CreateKeyResponse { id, key }))
}

async fn list_keys(State(state): State<AppState>) -> impl IntoResponse {
    let keys = state.proxy.all_keys().await;
    let items: Vec<KeyListItem> = keys
        .into_iter()
        .map(|k| KeyListItem {
            id: k.id,
            key_prefix: format!("{}***", k.key_prefix),
            sandbox_id: k.sandbox_id,
            created_at: k.created_at,
            expires_at: k.expires_at,
            revoked: k.revoked,
        })
        .collect();
    Json(items)
}

async fn revoke_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    if state.proxy.revoke_key(&key_id).await {
        (StatusCode::OK, Json(json!({"status":"revoked"}))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"key not found"})),
        )
            .into_response()
    }
}

async fn chat_completions(
    State(state): State<AppState>,
    auth: VirtualKeyAuth,
    body: Bytes,
) -> Response {
    let rate_key = format!(
        "{}:{}",
        auth.key_id,
        auth.sandbox_id.clone().unwrap_or_default()
    );
    if let Err((code, payload)) = state.rate_limit.check_rate_limit(&rate_key).await {
        return (code, [("content-type", "application/json")], payload).into_response();
    }

    let started_at = Instant::now();
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid json body: {err}")})),
            )
                .into_response();
        }
    };

    let model = payload
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("gpt-4o-mini")
        .to_string();
    let is_stream = payload
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if is_stream {
        let provider = provider_for_model(&model, &state.proxy.default_provider);
        let endpoint = provider_endpoint(&provider.name);
        let mut request = state.proxy.http_client.post(endpoint).body(body.clone());

        request = if provider.name == "anthropic" {
            request
                .header("x-api-key", &state.proxy.provider_api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
        } else {
            request
                .header(
                    "authorization",
                    format!("Bearer {}", state.proxy.provider_api_key),
                )
                .header("content-type", "application/json")
        };

        match request.send().await {
            Ok(upstream) => {
                info!(
                    key_id = %auth.key_id,
                    model = %model,
                    latency_ms = started_at.elapsed().as_millis() as u64,
                    "stream proxy request completed"
                );
                stream_response(upstream).await
            }
            Err(err) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("upstream stream failed: {err}")})),
            )
                .into_response(),
        }
    } else {
        match proxy_request(&state.proxy, &auth, body, &model).await {
            Ok(response) => {
                let token_usage = payload
                    .get("max_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                info!(
                    key_id = %auth.key_id,
                    model = %model,
                    token_usage = token_usage,
                    latency_ms = started_at.elapsed().as_millis() as u64,
                    "proxy request completed"
                );
                response
            }
            Err(err) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": err.to_string()})),
            )
                .into_response(),
        }
    }
}

fn random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn unix_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        num::NonZeroU32,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    const ADMIN_TOKEN: &str = "test-admin-token";

    use agent_seal_core::error::SealError;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use bytes::Bytes;
    use reqwest::{Client, Proxy};
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tower::ServiceExt;

    use super::{
        AppState, build_router_with_admin_token, random_string, resolve_admin_token, unix_ts_secs,
    };
    use crate::{
        auth::VirtualKeyAuth,
        provider::{ProviderConfig, provider_endpoint, provider_for_model, proxy_request},
        rate_limit::RateLimitLayer,
        state::{ProxyState, VirtualKey},
        stream::stream_response,
        try_create_app_with_admin_token,
    };

    async fn response_json(response: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn app_with_valid_key(client: Client, default_provider: &str) -> axum::Router {
        let mut state = ProxyState::new("provider-key".to_string(), default_provider.to_string());
        state.http_client = client;
        state
            .add_key(VirtualKey::new(
                "key-1".to_string(),
                "as-valid",
                Some("sbx-1".to_string()),
                1,
                u64::MAX,
            ))
            .await;
        try_create_app_with_admin_token(state, Some(ADMIN_TOKEN.to_string()))
            .expect("app should build when admin token is provided")
    }

    fn failing_http_client() -> Client {
        Client::builder()
            .proxy(Proxy::all("http://127.0.0.1:1").unwrap())
            .build()
            .unwrap()
    }

    async fn spawn_chunked_server(chunks: Vec<Vec<u8>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request_buf = [0_u8; 1024];
            let _ = socket.read(&mut request_buf).await;

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            for chunk in chunks {
                let header = format!("{:X}\r\n", chunk.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }

            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });

        format!("http://{addr}")
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some(ADMIN_TOKEN.to_string()),
        )
        .expect("app should build when admin token is provided");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["status"], "ok");
    }

    #[tokio::test]
    async fn admin_keys_create_and_list() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some(ADMIN_TOKEN.to_string()),
        )
        .expect("app should build when admin token is provided");
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-admin-token")
                    .body(Body::from(r#"{"sandbox_id":"sbx-1","ttl_secs":3600}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created = response_json(create_response).await;
        assert!(created["id"].as_str().is_some());

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/keys")
                    .header("authorization", "Bearer test-admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let listed = response_json(list_response).await;
        assert!(listed.as_array().is_some());
    }

    #[tokio::test]
    async fn admin_keys_revoke_key() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some(ADMIN_TOKEN.to_string()),
        )
        .expect("app should build when admin token is provided");
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-admin-token")
                    .body(Body::from(r#"{"sandbox_id":"sbx-1","ttl_secs":3600}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created = response_json(create_response).await;
        let key_id = created["id"].as_str().unwrap().to_string();

        let revoke_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/keys/{key_id}"))
                    .header("authorization", "Bearer test-admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn chat_completions_without_auth_returns_401() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some(ADMIN_TOKEN.to_string()),
        )
        .expect("app should build when admin token is provided");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"model":"gpt-4o-mini","messages":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn provider_for_model_routes_expected_models() {
        let claude = provider_for_model("claude-3-5-sonnet", "openai");
        assert_eq!(claude.name, "anthropic");

        let gpt = provider_for_model("gpt-4o-mini", "anthropic");
        assert_eq!(gpt.name, "openai");

        let o1 = provider_for_model("o1-mini", "anthropic");
        assert_eq!(o1.name, "openai");

        let unknown_openai = provider_for_model("custom-model", "openai");
        assert_eq!(unknown_openai.name, "openai");

        let unknown_anthropic = provider_for_model("custom-model", "anthropic");
        assert_eq!(unknown_anthropic.name, "anthropic");
    }

    #[test]
    fn provider_endpoint_returns_expected_urls() {
        assert_eq!(
            provider_endpoint("anthropic"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            provider_endpoint("openai"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            provider_endpoint("anything-else"),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn provider_config_struct_fields_are_accessible() {
        let config = ProviderConfig {
            name: "openai".to_string(),
            base_url: "https://api.openai.com".to_string(),
            api_key_header: "Authorization".to_string(),
            models: vec!["gpt-4o-mini".to_string()],
        };

        assert_eq!(config.name, "openai");
        assert_eq!(config.base_url, "https://api.openai.com");
        assert_eq!(config.api_key_header, "Authorization");
        assert_eq!(config.models, vec!["gpt-4o-mini".to_string()]);
    }

    #[tokio::test]
    async fn proxy_request_rejects_invalid_openai_header_value() {
        let state = ProxyState::new("bad\nkey".to_string(), "openai".to_string());
        let auth = VirtualKeyAuth {
            key_id: "key-1".to_string(),
            sandbox_id: Some("sbx-1".to_string()),
        };

        let err = proxy_request(
            &state,
            &auth,
            Bytes::from_static(br#"{"model":"gpt-4o-mini"}"#),
            "gpt-4o-mini",
        )
        .await
        .expect_err("invalid header value should fail before network call");

        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn proxy_request_rejects_invalid_anthropic_header_value() {
        let state = ProxyState::new("bad\nkey".to_string(), "anthropic".to_string());
        let auth = VirtualKeyAuth {
            key_id: "key-1".to_string(),
            sandbox_id: Some("sbx-1".to_string()),
        };

        let err = proxy_request(
            &state,
            &auth,
            Bytes::from_static(br#"{"model":"claude-3-haiku"}"#),
            "claude-3-haiku",
        )
        .await
        .expect_err("invalid header value should fail before network call");

        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn random_string_uses_expected_format_and_varies() {
        let samples: Vec<String> = (0..20).map(|_| random_string(24)).collect();
        assert!(
            samples
                .iter()
                .all(|s| s.len() == 24 && s.chars().all(|c| c.is_ascii_alphanumeric()))
        );

        let unique_count = samples.into_iter().collect::<HashSet<_>>().len();
        assert!(unique_count > 1);
    }

    #[test]
    fn unix_ts_secs_is_close_to_current_time() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        let ts = unix_ts_secs();

        assert!(ts <= now.saturating_add(2));
        assert!(ts.saturating_add(2) >= now);
    }

    #[tokio::test]
    async fn chat_completions_invalid_json_returns_400() {
        let app = app_with_valid_key(Client::new(), "openai").await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer as-valid")
                    .header("content-type", "application/json")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response_json(response).await["error"]
                .as_str()
                .unwrap()
                .contains("invalid json body")
        );
    }

    #[tokio::test]
    async fn chat_completions_stream_true_upstream_failure_returns_502() {
        let app = app_with_valid_key(failing_http_client(), "openai").await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer as-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"model":"gpt-4o-mini","messages":[],"stream":true}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            response_json(response).await["error"]
                .as_str()
                .unwrap()
                .contains("upstream stream failed")
        );
    }

    #[tokio::test]
    async fn chat_completions_stream_true_with_anthropic_model_upstream_failure_returns_502() {
        let app = app_with_valid_key(failing_http_client(), "openai").await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer as-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"model":"claude-3-haiku","messages":[],"stream":true}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            response_json(response).await["error"]
                .as_str()
                .unwrap()
                .contains("upstream stream failed")
        );
    }

    #[tokio::test]
    async fn chat_completions_stream_false_upstream_failure_returns_502() {
        let app = app_with_valid_key(failing_http_client(), "openai").await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer as-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"model":"gpt-4o-mini","messages":[],"stream":false}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            response_json(response).await["error"]
                .as_str()
                .unwrap()
                .contains("upstream request failed")
        );
    }

    #[tokio::test]
    async fn authenticated_probe_with_valid_key_returns_200() {
        let app = app_with_valid_key(Client::new(), "openai").await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_test/authenticated")
                    .header("authorization", "Bearer as-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["status"], "authorized");
    }

    #[tokio::test]
    async fn build_router_returns_router_that_serves_health() {
        let app = build_router_with_admin_token(
            AppState {
                proxy: ProxyState::new("provider-key".to_string(), "openai".to_string()),
                rate_limit: RateLimitLayer::new(
                    NonZeroU32::new(10).unwrap(),
                    NonZeroU32::new(2).unwrap(),
                ),
            },
            ADMIN_TOKEN.to_string(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn resolve_admin_token_fails_without_env_value() {
        let err = resolve_admin_token(None).expect_err("missing admin token should fail");

        assert!(
            matches!(err, SealError::InvalidInput(message) if message.contains("AGENT_SEAL_ADMIN_TOKEN"))
        );
    }

    #[tokio::test]
    async fn stream_response_handles_chunk_boundaries_and_empty_lines() {
        let url =
            spawn_chunked_server(vec![b"data: one\n\ndata: t".to_vec(), b"wo\n\n".to_vec()]).await;
        let upstream = reqwest::get(url).await.unwrap();
        let response = stream_response(upstream).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap(),
            "text/event-stream"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "data: one\ndata: two\n"
        );
    }

    #[tokio::test]
    async fn stream_response_flushes_trailing_partial_line() {
        let url = spawn_chunked_server(vec![b"data: trailing".to_vec()]).await;
        let upstream = reqwest::get(url).await.unwrap();
        let response = stream_response(upstream).await;

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "data: trailing\n");
    }
}
