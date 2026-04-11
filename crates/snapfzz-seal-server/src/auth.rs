//! Bearer token authentication middleware for API routes.
//!
//! When the `SNAPFZZ_SEAL_API_KEY` environment variable is set, every request
//! to a protected route must include a matching `Authorization: Bearer <token>`
//! header.  If the variable is absent the server runs in **dev mode** — auth is
//! skipped and a warning is logged once at startup.
//!
//! Timing-safe comparison is performed via [`subtle::ConstantTimeEq`] to
//! prevent token-length leaks.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use futures::future::BoxFuture;
use serde_json::json;
use subtle::ConstantTimeEq;
use tower::{Layer, Service};
use tracing::warn;

/// Optional API key stored in server state.  `None` means dev-mode (no auth).
pub type ApiKey = Option<Arc<String>>;

/// Read `SNAPFZZ_SEAL_API_KEY` from the environment.
///
/// Returns `None` if the variable is absent (dev mode) and logs a warning.
pub fn load_api_key() -> ApiKey {
    match std::env::var("SNAPFZZ_SEAL_API_KEY") {
        Ok(v) if !v.is_empty() => Some(Arc::new(v)),
        _ => {
            warn!(
                "SNAPFZZ_SEAL_API_KEY is not set — \
                 Bearer token authentication is DISABLED (dev mode only)"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Layer / middleware
// ---------------------------------------------------------------------------

/// A [`Tower`] layer that enforces Bearer token authentication.
///
/// Pass the value from [`load_api_key`].  When `api_key` is `None` the layer
/// is a transparent passthrough (dev mode).
#[derive(Clone)]
pub struct BearerAuthLayer {
    api_key: ApiKey,
}

impl BearerAuthLayer {
    /// Create a new layer.  `api_key = None` disables auth.
    pub fn new(api_key: ApiKey) -> Self {
        Self { api_key }
    }
}

impl<S> Layer<S> for BearerAuthLayer {
    type Service = BearerAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BearerAuthMiddleware {
            inner,
            api_key: self.api_key.clone(),
        }
    }
}

/// Middleware produced by [`BearerAuthLayer`].
#[derive(Clone)]
pub struct BearerAuthMiddleware<S> {
    inner: S,
    api_key: ApiKey,
}

impl<S> Service<Request<Body>> for BearerAuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Dev mode: no key configured → pass through.
        let Some(expected) = self.api_key.clone() else {
            return Box::pin(self.inner.call(req));
        };

        // Extract the Bearer token from the Authorization header.
        let token_matches = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|provided| {
                // Constant-time comparison.
                provided
                    .as_bytes()
                    .ct_eq(expected.as_bytes())
                    .into()
            })
            .unwrap_or(false);

        if token_matches {
            Box::pin(self.inner.call(req))
        } else {
            Box::pin(async move {
                let body = json!({"error": "unauthorized"}).to_string();
                Ok(axum::http::Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("response should build")
                    .into_response())
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    use super::*;

    fn make_app(api_key: ApiKey) -> Router {
        Router::new()
            .route("/api/v1/ping", get(|| async { "pong" }))
            .layer(BearerAuthLayer::new(api_key))
    }

    async fn send(app: Router, auth_header: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri("/api/v1/ping");
        if let Some(h) = auth_header {
            builder = builder.header(axum::http::header::AUTHORIZATION, h);
        }
        let req = builder.body(Body::empty()).expect("request should build");
        app.oneshot(req)
            .await
            .expect("request should succeed")
            .status()
    }

    #[tokio::test]
    async fn correct_token_returns_200() {
        let key = ApiKey::Some(Arc::new("secret-token".to_string()));
        let app = make_app(key);
        assert_eq!(send(app, Some("Bearer secret-token")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_token_returns_401() {
        let key = ApiKey::Some(Arc::new("secret-token".to_string()));
        let app = make_app(key);
        assert_eq!(send(app, None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let key = ApiKey::Some(Arc::new("secret-token".to_string()));
        let app = make_app(key);
        assert_eq!(
            send(app, Some("Bearer wrong-token")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn dev_mode_no_key_passes_through() {
        let app = make_app(None);
        assert_eq!(send(app, None).await, StatusCode::OK);
    }
}
