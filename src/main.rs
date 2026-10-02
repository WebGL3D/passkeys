mod controllers;
mod cookies;
mod db;
mod env;
mod webauthn;

use crate::controllers::passkeys::{initiate_login, signup};
use crate::controllers::users::{authenticated_user, update_email};
use axum::{
    Router,
    routing::{get, post},
};

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!(
        "listening on {} (until SIGTERM)",
        listener.local_addr().unwrap()
    );
    axum::serve(listener, router())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    println!("container is shutting down");
}

fn router() -> Router {
    Router::new()
        .route("/api/v1/users/authenticated", get(authenticated_user))
        .route("/api/v1/users/email", post(update_email))
        .route("/api/v1/passkeys/initiate-login", get(initiate_login))
        .route("/api/v1/passkeys/signup", post(signup))
}

async fn shutdown_signal() {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler")
        .recv()
        .await;
}
