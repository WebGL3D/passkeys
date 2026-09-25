use crate::env::{HELLO};
use axum::{Json};
use serde::{Serialize};

#[derive(Serialize)]
pub struct Metadata {
    #[serde(rename = "example")]
    example: String,
}

/// The metadata endpoint used by the web app to load the VAPID public key.
pub async fn metadata() -> Json<Metadata> {
    Json(Metadata {
        example: HELLO.to_string(),
    })
}
