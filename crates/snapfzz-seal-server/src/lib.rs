pub mod auth;
pub mod routes;
#[path = "sandbox.rs"]
pub mod sandbox;
pub mod state;

use axum::Router;
use routes::build_router;
use state::ServerState;

pub fn create_app(state: ServerState) -> Router {
    build_router(state)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::{ServerState, create_app};

    // ---------------------------------------------------------------------------
    // Health route (no auth)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn create_app_serves_health_route() {
        let root = std::env::temp_dir().join("snapfzz-seal-server-lib-tests");
        let app = create_app(ServerState::new(root.join("compile"), root.join("output")));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ---------------------------------------------------------------------------
    // Bearer token authentication on /api/v1/* routes
    // ---------------------------------------------------------------------------

    fn state_with_key(key: &str) -> ServerState {
        let root = std::env::temp_dir().join("snapfzz-seal-server-auth-tests");
        ServerState::new(root.join("compile"), root.join("output"))
            .with_api_key(Some(Arc::new(key.to_string())))
    }

    fn state_no_key() -> ServerState {
        let root = std::env::temp_dir().join("snapfzz-seal-server-auth-tests");
        ServerState::new(root.join("compile"), root.join("output"))
    }

    async fn get_status(app: axum::Router, uri: &str, auth: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri(uri);
        if let Some(h) = auth {
            builder = builder.header(axum::http::header::AUTHORIZATION, h);
        }
        let req = builder.body(Body::empty()).expect("request should build");
        app.oneshot(req)
            .await
            .expect("request should succeed")
            .status()
    }

    #[tokio::test]
    async fn correct_bearer_token_returns_non_401_on_api_route() {
        let app = create_app(state_with_key("my-secret"));
        // The route returns 404 because job doesn't exist — that is fine, it
        // means auth passed and the handler ran.
        let status = get_status(app, "/api/v1/jobs/nonexistent", Some("Bearer my-secret")).await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_bearer_token_returns_401_on_api_route() {
        let app = create_app(state_with_key("my-secret"));
        let status = get_status(app, "/api/v1/jobs/nonexistent", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_bearer_token_returns_401_on_api_route() {
        let app = create_app(state_with_key("my-secret"));
        let status = get_status(app, "/api/v1/jobs/nonexistent", Some("Bearer wrong-secret")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dev_mode_no_key_allows_api_route() {
        let app = create_app(state_no_key());
        // No key set → dev mode, auth skipped; route returns 404 (no such job)
        let status = get_status(app, "/api/v1/jobs/nonexistent", None).await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);
    }
}
