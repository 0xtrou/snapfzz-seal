use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::state::{ProxyState, VirtualKey};

#[derive(Clone, Debug)]
pub struct VirtualKeyAuth {
    pub key_id: String,
    pub sandbox_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AdminAuth;

impl<S> FromRequestParts<S> for VirtualKeyAuth
where
    S: Send + Sync,
    ProxyState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = ProxyState::from_ref(state);
        let token = bearer_token(parts).unwrap_or_default();

        if token.is_empty() {
            return Err(invalid_key_response());
        }

        let key = validate_key(&state, token)
            .await
            .ok_or_else(invalid_key_response)?;

        Ok(VirtualKeyAuth {
            key_id: key.id,
            sandbox_id: key.sandbox_id,
        })
    }
}

impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
    String: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let admin_token = String::from_ref(state);
        let token = bearer_token(parts).unwrap_or_default();

        if token.is_empty() {
            return Err(invalid_admin_response());
        }

        let candidate_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let expected_hash: [u8; 32] = Sha256::digest(admin_token.as_bytes()).into();
        if candidate_hash.ct_eq(&expected_hash).into() {
            Ok(AdminAuth)
        } else {
            Err(invalid_admin_response())
        }
    }
}

pub async fn validate_key(state: &ProxyState, token: &str) -> Option<VirtualKey> {
    let candidate_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let now = unix_ts_secs();

    state
        .keys
        .read()
        .await
        .get(&candidate_hash)
        .filter(|key| {
            key.key_hash.ct_eq(&candidate_hash).into() && !key.revoked && key.expires_at > now
        })
        .cloned()
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
}

fn unix_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn invalid_key_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "invalid or expired key"})),
    )
        .into_response()
}

fn invalid_admin_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "invalid admin token"})),
    )
        .into_response()
}

pub async fn admin_auth_middleware(
    State(admin_token): State<String>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let outcome = AdminAuth::from_request_parts(&mut parts, &admin_token).await;
    req = axum::http::Request::from_parts(parts, body);

    match outcome {
        Ok(_) => next.run(req).await,
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::{
            admin_auth_middleware, bearer_token, invalid_admin_response, invalid_key_response,
            validate_key,
        },
        state::{ProxyState, VirtualKey},
        try_create_app_with_admin_token,
    };
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::get,
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    fn build_key(id: &str, plaintext: &str, expires_at: u64, revoked: bool) -> VirtualKey {
        let mut key = VirtualKey::new(
            id.to_string(),
            plaintext,
            Some("sbx-1".to_string()),
            1,
            expires_at,
        );
        key.revoked = revoked;
        key
    }

    #[tokio::test]
    async fn valid_key_passes() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state
            .add_key(build_key("key-1", "as-valid", u64::MAX, false))
            .await;
        let app = try_create_app_with_admin_token(state, Some("test-admin-token".to_string()))
            .expect("app should build when admin token is provided");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_test/authenticated")
                    .method("GET")
                    .header("authorization", "Bearer as-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_key_returns_401() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some("test-admin-token".to_string()),
        )
        .expect("app should build when admin token is provided");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .header("authorization", "Bearer as-invalid")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_key_returns_401() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some("test-admin-token".to_string()),
        )
        .expect("app should build when admin token is provided");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_requires_proper_prefix_and_header() {
        let req = Request::builder()
            .header("authorization", "Bearer token-1")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), Some("token-1"));

        let req = Request::builder()
            .header("authorization", "Basic token-1")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), None);

        let req = Request::builder().body(Body::empty()).unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(bearer_token(&parts), None);
    }

    #[tokio::test]
    async fn validate_key_returns_none_for_hash_mismatch() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        let mut key = build_key("key-1", "as-valid", u64::MAX, false);
        key.key_hash = Sha256::digest(b"different").into();
        state.add_key(key).await;

        assert!(validate_key(&state, "as-valid").await.is_none());
    }

    #[tokio::test]
    async fn expired_key_returns_401() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state
            .add_key(build_key("key-1", "as-expired", 0, false))
            .await;
        let app = try_create_app_with_admin_token(state, Some("test-admin-token".to_string()))
            .expect("app should build when admin token is provided");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .header("authorization", "Bearer as-expired")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_key_returns_401() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state
            .add_key(build_key("key-1", "as-revoked", u64::MAX, true))
            .await;
        let app = try_create_app_with_admin_token(state, Some("test-admin-token".to_string()))
            .expect("app should build when admin token is provided");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .header("authorization", "Bearer as-revoked")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn invalid_key_response_has_expected_shape() {
        let response = invalid_key_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn invalid_admin_response_has_expected_shape() {
        let response = invalid_admin_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    async fn ok_handler() -> impl IntoResponse {
        (StatusCode::OK, "ok")
    }

    #[tokio::test]
    async fn admin_auth_middleware_rejects_bad_token() {
        let app = Router::new()
            .route("/admin", get(ok_handler))
            .layer(from_fn_with_state(
                "secret-token".to_string(),
                admin_auth_middleware,
            ))
            .with_state(());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_auth_middleware_accepts_good_token() {
        let app = Router::new()
            .route("/admin", get(ok_handler))
            .layer(from_fn_with_state(
                "secret-token".to_string(),
                admin_auth_middleware,
            ))
            .with_state(());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
