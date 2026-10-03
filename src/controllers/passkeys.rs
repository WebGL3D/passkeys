use crate::cookies::{authenticate, fetch};
use crate::db::{create_challenge, insert_passkey, redeem_challenge, select_passkeys};
use crate::env::{HOST_NAME, ORIGIN};
use crate::webauthn::{parse_attestation_object, parse_authenticator_data};
use axum::{
    Json,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use email_address::{EmailAddress, Options};
use pem::{Pem, encode};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error};
use uuid::Uuid;

const PUBLIC_KEY_TYPE: &str = "public-key";
const UNEXPECTED_ERROR: &str = "An unexpected error occurred, please try again.";

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
    pub timeout: u64,
}

#[derive(Deserialize)]
pub struct CredentialCreateResponse {
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

/// Maps to [AuthenticatorResponse.clientDataJSON](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON)
#[derive(Serialize, Deserialize)]
pub struct ClientData {
    /// `webauthn.create` OR `webauthn.get`
    #[serde(rename = "type")]
    authn_type: String,

    /// The challenge token.
    challenge: String,

    /// The origin the passkey was created on.
    origin: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    id: String,

    #[serde(rename = "rawId")]
    raw_id: String,

    response: CredentialCreateResponse,
}

/// Error JSON result.
#[derive(Serialize)]
pub struct ErrorJson {
    /// Error message.
    error: String,
}

/// The endpoint used by the web app to load passkey information about the user, from their email address.
pub async fn initiate_login(Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
    let email = match fetch_email(query) {
        Ok(e) => e,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ErrorJson { error: e })).into_response(),
    };

    let challenge = match create_challenge(email.clone()).await {
        Ok(c) => c,
        Err(err) => {
            println!("Failed to create challenge: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    error: String::from(UNEXPECTED_ERROR),
                }),
            )
                .into_response();
        }
    };

    let passkeys: Vec<String> = match select_passkeys(email).await {
        Ok(response) => response.into_iter().map(|p| p.id).collect(),
        Err(e) => {
            println!(
                "Failed to send query back to container: {} - {}",
                e.to_string(),
                e.source().unwrap()
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    error: String::from(UNEXPECTED_ERROR),
                }),
            )
                .into_response();
        }
    };

    Json(LoginMetadata {
        user_id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        challenge: challenge.id,
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
        // 1 second accounting for latency
        timeout: challenge.expiration - ((Utc::now().timestamp() * 1000) as u64) - 1000,
        available_public_keys: passkeys,
    })
    .into_response()
}

/// Creates a new user, with their registered passkey.
pub async fn signup(
    cookies: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    Json(request): Json<SignupRequest>,
) -> (CookieJar, impl IntoResponse) {
    if fetch(cookies.clone()).is_ok() {
        return (
            cookies,
            (
                StatusCode::FORBIDDEN,
                Json(ErrorJson {
                    error: String::from("Authenticated user cannot signup."),
                }),
            )
                .into_response(),
        );
    }

    let email = match fetch_email(query) {
        Ok(email) => email,
        Err(e) => {
            return (
                cookies,
                (StatusCode::BAD_REQUEST, Json(ErrorJson { error: e })).into_response(),
            );
        }
    };

    if match select_passkeys(email.clone()).await {
        Ok(response) => response.len() > 0,
        Err(err) => {
            println!("Failed to query for existing passkeys: {err}");
            return (
                cookies,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: String::from(UNEXPECTED_ERROR),
                    }),
                )
                    .into_response(),
            );
        }
    } {
        // Can't sign up with passkey if the email already has a passkey associated with it.
        return (
            cookies,
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: String::from(
                        "Passkey already exists for email address, sign in instead.",
                    ),
                }),
            )
                .into_response(),
        );
    }

    let client_data = match parse_client_data(request.response.client_data_json, "webauthn.create")
    {
        Ok(c) => c,
        Err(err) => {
            println!("Failed to parse clientDataJSON: {err}");
            return (
                cookies,
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: String::from("Invalid clientDataJSON"),
                    }),
                )
                    .into_response(),
            );
        }
    };

    let challenge = match redeem_challenge(client_data.challenge.clone(), email.clone()).await {
        Ok(c) => c,
        Err(err) => {
            println!("Failed to redeem challenge: {err}");
            return (
                cookies,
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: String::from("Invalid challenge token"),
                    }),
                )
                    .into_response(),
            );
        }
    };

    let authenticator_data = match parse_authenticator_data(request.response.authenticator_data) {
        Ok(a) => a,
        Err(err) => {
            println!("Failed to parse authenticatorData: {err}");
            return (
                cookies,
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: String::from("Invalid authenticatorData"),
                    }),
                )
                    .into_response(),
            );
        }
    };

    println!("challenge: {}", challenge.id);
    println!("email: {}", email);
    println!("Host: {}", ORIGIN.as_str());
    println!("clientDataJSON: {:?}", serde_json::to_string(&client_data));
    println!(
        "flags ({}): {}",
        authenticator_data.flags.iter().count(),
        authenticator_data
            .flags
            .iter()
            .map(|f| format!("{:?}", f))
            .collect::<Vec<String>>()
            .join(", ")
    );
    println!("sign_count: {}", authenticator_data.sign_count);
    println!(
        "authenticator_attestation_guid: {:?}",
        authenticator_data.authenticator_attestation_guid
    );
    println!("credential_id: {:?}", authenticator_data.credential_id);
    println!(
        "credential_public_key: {:?}",
        authenticator_data.credential_public_key
    );

    let attestation_object = match parse_attestation_object(request.response.attestation_object) {
        Ok(a) => a,
        Err(err) => {
            println!("Failed to parse attestationObject: {err}");
            return (
                cookies,
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: String::from("Invalid attestationObject"),
                    }),
                )
                    .into_response(),
            );
        }
    };
    println!("attestationObject.fmt: {}", attestation_object.format);

    let public_key = match parse_public_key(
        request.response.public_key,
        request.response.public_key_algorithm,
    ) {
        Ok(public_key) => encode(&public_key),
        Err(res) => return (cookies, res),
    };

    println!("public_key: {public_key}");
    match insert_passkey(
        attestation_object,
        public_key,
        request.response.public_key_algorithm,
        email.to_string(),
    )
    .await
    {
        Ok(_) => match authenticate(cookies.clone(), email) {
            Ok(c) => (c, StatusCode::CREATED.into_response()),
            Err(err) => {
                println!("Failed to update cookie jar after passkey saved: {err}");
                (
                    cookies,
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorJson {
                            error: UNEXPECTED_ERROR.to_string(),
                        }),
                    )
                        .into_response(),
                )
            }
        },
        Err(err) => {
            println!("Failed to save passkey to database: {err}");
            (
                cookies,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: UNEXPECTED_ERROR.to_string(),
                    }),
                )
                    .into_response(),
            )
        }
    }
}

fn parse_public_key(base64: String, _algorithm: i32) -> Result<Pem, Response> {
    // TODO: Figure out what to do with the public key algorithm
    match URL_SAFE_NO_PAD.decode(base64) {
        // TODO: Verify the "PUBLIC KEY" tag is what we need here
        Ok(bytes) => Ok(Pem::new("PUBLIC KEY", bytes)),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorJson {
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

fn parse_client_data(client_data_json: String, expected_type: &str) -> Result<ClientData, String> {
    let client_data = match URL_SAFE_NO_PAD.decode(client_data_json) {
        Ok(json_bytes) => String::from_utf8(json_bytes),
        Err(_) => return Err(String::from("Failed base64 decode")),
    };

    let json = match client_data {
        Ok(json) => serde_json::from_str::<ClientData>(json.as_str()),
        Err(_) => return Err(String::from("Failed String::from_utf8")),
    };

    match json {
        Ok(client_data) => {
            if !client_data.authn_type.eq(expected_type) {
                return Err(String::from("authn type did not match"));
            }

            if !client_data.origin.eq(ORIGIN.as_str().trim_end_matches("/")) {
                return Err(String::from("origin did not match"));
            }

            Ok(client_data)
        }
        Err(_) => Err(String::from("serde_json::from_str")),
    }
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
}
