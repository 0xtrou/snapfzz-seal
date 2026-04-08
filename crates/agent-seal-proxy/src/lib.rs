pub mod auth;
pub mod provider;
pub mod rate_limit;
pub mod routes;
pub mod state;
pub mod stream;

use std::num::NonZeroU32;

use agent_seal_core::error::SealError;
use axum::Router;
use rate_limit::RateLimitLayer;
use routes::{AppState, build_router_with_admin_token, resolve_admin_token};
use state::ProxyState;

pub fn create_app(state: ProxyState) -> Router {
    try_create_app(state)
        .expect("AGENT_SEAL_ADMIN_TOKEN env var is required to start agent-seal-proxy")
}

pub fn try_create_app(state: ProxyState) -> Result<Router, SealError> {
    try_create_app_with_admin_token(state, std::env::var("AGENT_SEAL_ADMIN_TOKEN").ok())
}

pub fn try_create_app_with_admin_token(
    state: ProxyState,
    admin_token: Option<String>,
) -> Result<Router, SealError> {
    let app_state = AppState {
        proxy: state,
        rate_limit: RateLimitLayer::new(
            NonZeroU32::new(10).expect("non zero"),
            NonZeroU32::new(2).expect("non zero"),
        ),
    };
    let admin_token = resolve_admin_token(admin_token)?;
    Ok(build_router_with_admin_token(app_state, admin_token))
}

#[cfg(test)]
mod tests {
    use agent_seal_core::error::SealError;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::{ProxyState, try_create_app_with_admin_token};

    #[tokio::test]
    async fn create_app_serves_health_route() {
        let app = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            Some("test-admin-token".to_string()),
        )
        .expect("app should build when admin token is configured");

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

    #[test]
    fn create_app_fails_without_admin_token_env_var() {
        let err = try_create_app_with_admin_token(
            ProxyState::new("provider-key".to_string(), "openai".to_string()),
            None,
        )
        .expect_err("app should fail without admin token env var");

        assert!(
            matches!(err, SealError::InvalidInput(message) if message.contains("AGENT_SEAL_ADMIN_TOKEN"))
        );
    }
}
