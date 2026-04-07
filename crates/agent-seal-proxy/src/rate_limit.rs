use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct RateLimitLayer {
    limiters: Arc<RwLock<HashMap<String, RateLimiterState>>>,
    max_burst: NonZeroU32,
    per_second: NonZeroU32,
    global_limiter: Arc<DefaultDirectRateLimiter>,
}

#[derive(Clone)]
struct RateLimiterState {
    limiter: Arc<DefaultDirectRateLimiter>,
    last_access: Instant,
}

impl RateLimitLayer {
    pub fn new(max_burst: NonZeroU32, per_second: NonZeroU32) -> Self {
        let quota = Quota::per_second(per_second).allow_burst(max_burst);
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
            max_burst,
            per_second,
            global_limiter: Arc::new(RateLimiter::direct(quota)),
        }
    }

    pub async fn check_rate_limit(&self, key_id: &str) -> Result<(), (StatusCode, String)> {
        self.global_limiter
            .check()
            .map_err(limit_exceeded_response)?;

        let limiter = self.get_or_create_limiter(key_id).await;
        limiter.check().map_err(limit_exceeded_response)?;
        Ok(())
    }

    pub async fn cleanup_stale_limiters(&self, max_idle: Duration) {
        let cutoff = Instant::now() - max_idle;
        self.limiters
            .write()
            .await
            .retain(|_, state| state.last_access >= cutoff);
    }

    async fn get_or_create_limiter(&self, key_id: &str) -> Arc<DefaultDirectRateLimiter> {
        let now = Instant::now();
        if let Some(existing) = self.limiters.write().await.get_mut(key_id) {
            existing.last_access = now;
            return existing.limiter.clone();
        }

        let quota = Quota::per_second(self.per_second).allow_burst(self.max_burst);
        let limiter = Arc::new(RateLimiter::direct(quota));
        self.limiters.write().await.insert(
            key_id.to_string(),
            RateLimiterState {
                limiter: limiter.clone(),
                last_access: now,
            },
        );
        limiter
    }
}

fn limit_exceeded_response<T: governor::clock::Reference>(
    _: governor::NotUntil<T>,
) -> (StatusCode, String) {
    let retry_after_ms = Duration::from_secs(1).as_millis();
    (
        StatusCode::TOO_MANY_REQUESTS,
        format!("{{\"error\":\"rate limit exceeded\",\"retry_after_ms\":{retry_after_ms}}}"),
    )
}

#[cfg(test)]
mod tests {
    use super::RateLimitLayer;
    use axum::http::StatusCode;
    use std::{num::NonZeroU32, time::Duration};

    #[tokio::test]
    async fn under_limit_passes() {
        let layer = RateLimitLayer::new(NonZeroU32::new(10).unwrap(), NonZeroU32::new(2).unwrap());

        assert!(layer.check_rate_limit("key-1").await.is_ok());
        assert!(layer.check_rate_limit("key-1").await.is_ok());
    }

    #[tokio::test]
    async fn over_limit_returns_429() {
        let layer = RateLimitLayer::new(NonZeroU32::new(1).unwrap(), NonZeroU32::new(1).unwrap());
        assert!(layer.check_rate_limit("key-1").await.is_ok());

        let error = layer.check_rate_limit("key-1").await.unwrap_err();
        assert_eq!(error.0, StatusCode::TOO_MANY_REQUESTS);
        assert!(error.1.contains("rate limit exceeded"));
    }

    #[tokio::test]
    async fn different_keys_have_separate_limits() {
        let layer = RateLimitLayer::new(NonZeroU32::new(2).unwrap(), NonZeroU32::new(100).unwrap());
        assert!(layer.check_rate_limit("key-1").await.is_ok());
        assert!(layer.check_rate_limit("key-2").await.is_ok());
    }

    #[tokio::test]
    async fn cleanup_removes_stale_limiters() {
        let layer = RateLimitLayer::new(NonZeroU32::new(2).unwrap(), NonZeroU32::new(100).unwrap());
        assert!(layer.check_rate_limit("key-1").await.is_ok());

        tokio::time::sleep(Duration::from_millis(10)).await;
        layer.cleanup_stale_limiters(Duration::from_millis(1)).await;

        assert!(layer.limiters.read().await.is_empty());
    }
}
