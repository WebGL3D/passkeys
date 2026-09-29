use crate::env::HOST_NAME;
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use std::collections::HashMap;
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

/// The endpoint used by the web app to load passkey information about the user, from their email address.
pub async fn initiate_login(Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
    let email = match fetch_email(query) {
        Ok(email) => email,
        Err(e) => return e,
    };

    Json(LoginMetadata {
        user_id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        challenge: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        origin: HOST_NAME.to_string(),
        // These are the recommended algorithms: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#pubkeycredparams
        supported_public_keys: [
            PublicKeyParam {
                alg: -7, /* EdDSA */
                key_type: String::from(PUBLIC_KEY_TYPE),
            },
            PublicKeyParam {
                alg: -8, /* ES256 */
                key_type: String::from(PUBLIC_KEY_TYPE),
            },
            PublicKeyParam {
                alg: -257, /* RS256 */
                key_type: String::from(PUBLIC_KEY_TYPE),
            },
        ]
        .to_vec(),
        // Allow the challenge to exist for 5 minutes, before making the user start over.
        timeout: 300_000,
        // TODO: Fetch stored public keys for the user.
        available_public_keys: [].to_vec(),
    })
    .into_response()
}

fn fetch_email(query: HashMap<String, String>) -> Result<String, Response> {
    match query.get("email") {
        Some(email) => Ok(email.to_string()),
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: String::from("Invalid email"),
            }),
        )
            .into_response()),
    }
}
