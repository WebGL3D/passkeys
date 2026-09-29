use crate::env::{HOST_NAME, ORIGIN};
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use email_address::{EmailAddress, Options};
use pem::{Pem, encode};
use serde::{Deserialize, Serialize};
use sha2::Digest;
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

#[derive(Deserialize)]
pub struct CredentialResponse {
    #[serde(rename = "attestationObject")]
    attestation_object: String,

    #[serde(rename = "authenticatorData")]
    authenticator_data: String,

    #[serde(rename = "clientDataJSON")]
    client_data_json: String,

    #[serde(rename = "publicKey")]
    public_key: String,

    #[serde(rename = "publicKeyAlgorithm")]
    public_key_algorithm: i32,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    id: String,

    #[serde(rename = "rawId")]
    raw_id: String,

    response: CredentialResponse,
}

/// Error JSON result.
#[derive(Serialize)]
pub struct Error {
    /// Error message.
    error: String,
}

/// The endpoint used by the web app to load passkey information about the user, from their email address.
pub async fn initiate_login(Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
    let _email_hash = match fetch_email(query) {
        Ok(email) => hash_email(email),
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(Error { error: e })).into_response();
        }
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

/// Creates a new user, with their registered passkey.
pub async fn signup(
    Query(query): Query<HashMap<String, String>>,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let email = match fetch_email(query) {
        Ok(email) => email,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(Error { error: e })).into_response();
        }
    };

    println!("email: {}", email);
    println!("Host: {}", ORIGIN.as_str());
    println!(
        "clientDataJSON: {:?}",
        String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(request.response.client_data_json)
                .unwrap()
        )
    );
    println!(
        "authenticatorData: {:?}",
        URL_SAFE_NO_PAD
            .decode(request.response.authenticator_data)
            .unwrap()
    );
    println!(
        "attestationObject: {:?}",
        URL_SAFE_NO_PAD
            .decode(request.response.attestation_object)
            .unwrap()
    );

    match parse_public_key(
        request.response.public_key,
        request.response.public_key_algorithm,
    ) {
        Ok(public_key) => {
            println!("publicKey: {:?}", encode(&public_key));
        }
        Err(e) => return e,
    };

    StatusCode::CREATED.into_response()
}

fn parse_public_key(base64: String, _algorithm: i32) -> Result<Pem, Response> {
    // TODO: Figure out what to do with the public key algorithm
    match URL_SAFE_NO_PAD.decode(base64) {
        // TODO: Verify the "PUBLIC KEY" tag is what we need here
        Ok(bytes) => Ok(Pem::new("PUBLIC KEY", bytes)),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: String::from("Public key could not be parsed"),
            }),
        )
            .into_response()),
    }
}

/// Fetches and validates the email address from the query string.
fn fetch_email(query: HashMap<String, String>) -> Result<String, String> {
    let email = match query.get("email") {
        Some(email) => EmailAddress::parse_with_options(
            email,
            Options::default()
                .without_domain_literal()
                .without_display_text()
                .with_required_tld(),
        ),
        None => return Err(String::from("Invalid email")),
    };

    match email {
        Ok(email) => Ok(email.email()),
        Err(_) => Err(String::from("Invalid email")),
    }
}

/// Hashes an email address, so it can't be mapped back to its original value.
fn hash_email(email: String) -> String {
    let email_hash = sha2::Sha256::digest(format!("email:{email}").as_bytes());
    let email_hex = hex::encode(email_hash);

    // The first 32 characters should be reasonable enough for a demo...
    String::from(&email_hex[0..32])
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("", "Invalid email")]
    #[case("passkeys.webgl3d.dev", "Invalid email")]
    #[case("webgl3d@[127.0.0.1]", "Invalid email")]
    #[case("WebGL3D <vapid@webgl3d.dev>", "Invalid email")]
    #[case("vapid@webgl3d.dev", "vapid@webgl3d.dev")]
    fn test_fetch_email(#[case] query_value: String, #[case] expected: String) {
        let mut query: HashMap<String, String> = HashMap::new();
        if query_value.len() > 0 {
            query.insert(String::from("email"), query_value.to_string());
        }

        if query_value.contains(expected.as_str()) {
            assert_eq!(
                fetch_email(query),
                Ok(expected),
                "Expected email address was not returned"
            );
        } else {
            assert_eq!(
                fetch_email(query),
                Err(expected),
                "Expected error was not returned"
            );
        }
    }

    #[rstest]
    #[case("vapid@webgl3d.dev", "c9ca94190f3d5ef771f63acce3644c15")]
    fn test_hash_email(#[case] email: String, #[case] expected: String) {
        assert_eq!(hash_email(email), expected);
    }
}
