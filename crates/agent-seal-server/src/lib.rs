pub mod routes;
pub mod sandbox;
pub mod state;

use axum::Router;
use routes::build_router;
use state::ServerState;

pub fn create_app(state: ServerState) -> Router {
    build_router(state)
}
