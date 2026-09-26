use std::collections::HashMap;
use axum::{Json};
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Serialize};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD}, Engine};
use uuid::Uuid;

const PUBLIC_KEY_TYPE: &str = "public-key";

/// Item for [pubKeyCredParams](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#pubkeycredparams)
#[derive(Serialize, Clone)]
pub struct PublicKeyParam {
    /// A number that is equal to a [COSE Algorithm Identifier](https://www.iana.org/assignments/cose#algorithms).
    pub alg: i32,

    /// The only supported value for now is `public-key`.
    #[serde(rename = "type")]
    pub key_type: String,
}

/// Data that can be used to determine how the user should sign up or log in.
#[derive(Serialize)]
pub struct LoginMetadata {
    /// The user that is attempting to log in.
    #[serde(rename = "userId")]
    pub user_id: String,

    /// The authentication challenge ID.
    pub challenge: String,

    /// The origin to use as the `rpId`.
    pub origin: String,

    /// Maps to [pubKeyCredParams](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#pubkeycredparams)
    #[serde(rename = "pubKeyCredParams")]
    pub supported_public_keys: Vec<PublicKeyParam>,

    /// The IDs of the public keys that we can authenticate this user with.
    ///
    /// This will be empty if the email address is not associated with any public keys.
    #[serde(rename = "availablePublicKeys")]
    pub available_public_keys: Vec<String>,

    /// The timeout (in milliseconds) before the challenge is no longer valid.
    pub timeout: u32,
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
        user_id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        challenge: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        origin: host,
        // These are the recommended algorithms: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#pubkeycredparams
        supported_public_keys: [
            PublicKeyParam { alg: -7 /* EdDSA */, key_type: String::from(PUBLIC_KEY_TYPE) },
            PublicKeyParam { alg: -8 /* ES256 */, key_type: String::from(PUBLIC_KEY_TYPE) },
            PublicKeyParam { alg: -257 /* RS256 */, key_type: String::from(PUBLIC_KEY_TYPE) },
        ].to_vec(),
        // Allow the challenge to exist for 5 minutes, before making the user start over.
        timeout: 300_000,
        // TODO: Fetch stored public keys for the user.
        available_public_keys: [].to_vec()
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
