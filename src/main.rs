mod controllers;
mod cookies;
mod db;
mod env;
mod webauthn;

use crate::controllers::jwks::jwks;
use crate::controllers::passkeys::{initiate_login, signin, signout, signup};
use crate::controllers::users::{authenticated_user, delete_account, update_email};
use axum::{
    Router,
    routing::{delete, get, post},
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
        .route("/.well-known/jwks.json", get(jwks))
        .route("/api/v1/users/authenticated", get(authenticated_user))
        .route("/api/v1/users/authenticated", delete(delete_account))
        .route("/api/v1/users/email", post(update_email))
        .route("/api/v1/passkeys/initiate-login", get(initiate_login))
        .route("/api/v1/passkeys/signup", post(signup))
        .route("/api/v1/passkeys/signin", post(signin))
        .route("/api/v1/passkeys/signout", post(signout))
}

async fn shutdown_signal() {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler")
        .recv()
        .await;
}
