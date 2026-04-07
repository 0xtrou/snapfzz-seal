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

pub fn build_router(state: AppState) -> Router {
    let admin_token =
        std::env::var("AGENT_SEAL_ADMIN_TOKEN").unwrap_or_else(|_| "dev-admin-token".to_string());

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
    use crate::{create_app, state::ProxyState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    async fn response_json(response: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = create_app(ProxyState::new(
            "provider-key".to_string(),
            "openai".to_string(),
        ));
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
        let app = create_app(ProxyState::new(
            "provider-key".to_string(),
            "openai".to_string(),
        ));
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer dev-admin-token")
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
                    .header("authorization", "Bearer dev-admin-token")
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
        let app = create_app(ProxyState::new(
            "provider-key".to_string(),
            "openai".to_string(),
        ));
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer dev-admin-token")
                    .body(Body::from(r#"{"sandbox_id":"sbx-1","ttl_secs":3600}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created = response_json(create_response).await;
        let key_id = created["id"].as_str().unwrap().to_string();

        let _revoke_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/keys/{key_id}"))
                    .header("authorization", "Bearer dev-admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(_revoke_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn chat_completions_without_auth_returns_401() {
        let app = create_app(ProxyState::new(
            "provider-key".to_string(),
            "openai".to_string(),
        ));
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
}
