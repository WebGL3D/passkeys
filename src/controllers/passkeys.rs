use std::collections::HashMap;
use sha2::{Sha256, Digest};
use axum::{Json};
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Serialize};
use base64::{engine::general_purpose::URL_SAFE, Engine};

/// Maps with [PublicKeyCredentialCreationOptions.user](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#user)
#[derive(Serialize)]
pub struct User {
    /// The unique ID for the user account.
    pub id: String,

    /// For the purposes of this app, the user's email address.
    pub name: String,

    /// The user's preferred display name.
    #[serde(rename = "displayName")]
    pub display_name: String
}

#[derive(Serialize)]
pub struct LoginMetadata {
    /// The user that is attempting to log in.
    pub user: User,
}

/// Error JSON result.
#[derive(Serialize)]
pub struct Error {
    /// Error message.
    error: String,
}

/// The metadata endpoint used by the web app to load the VAPID public key.
pub async fn initiate_login(headers: HeaderMap, Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
    let email = match query.get("email") {
        Some(email) => email,
        None => return (StatusCode::BAD_REQUEST, Json(Error { error: String::from("Invalid email") })).into_response(),
    };

    let host = match host_name(headers) {
        Ok(host) => host,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(Error { error: e })).into_response(),
    };

    Json(LoginMetadata {
        user: User {
            id: URL_SAFE.encode(Sha256::digest(format!("{}:{}", host, email))),
            name: email.to_string(),
            display_name: String::from(""),
        }
    }).into_response()
}

/// Results in the Host header value (origin), without the port.
fn host_name(headers: HeaderMap) -> Result<String, String> {
    let header_value = match headers.get("Host") {
        Some(host) => host.to_str(),
        None => return Err(String::from("Missing Host header")),
    };

    // Remove port, if it's there
    let host = match header_value {
        Ok(host) => host.split(":").next(),
        Err(_) => return Err(String::from("Invalid Host header")),
    };

    // Pretty sure split(":") will always return at least one item, making
    // the "None" case here impossible, but this is technically correct.
    match host {
        Some(host) => Ok(String::from(host.to_string())),
        None => Err(String::from("Invalid Host header")),
    }
}

#[cfg(test)]
mod test {
    use axum::http::HeaderValue;
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("", "Missing Host header")]
    #[case("passkeys.webgl3d.dev", "passkeys.webgl3d.dev")]
    #[case("localhost:8080", "localhost")]
    fn test_host_name(#[case] header_value: String, #[case] expected: String) {
        let mut headers = HeaderMap::new();
        if header_value.len() > 0 {
            headers.append("Host", HeaderValue::from_str(header_value.as_str()).unwrap());
        }

        if header_value.contains(expected.as_str()) {
            assert_eq!(host_name(headers), Ok(expected));
        } else {
            assert_eq!(host_name(headers), Err(expected));
        }
    }
}
