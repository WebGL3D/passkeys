use crate::cookies::{authenticate, clear, fetch, get_cookie};
use crate::db::{
    create_challenge, delete_passkey as passkey_delete, insert_passkey, redeem_challenge,
    select_passkeys, select_user, update_sign_count,
};
use crate::env::HOST_NAME;
use crate::webauthn::{
    parse_attestation_object, parse_authenticator_data, parse_client_data, verify_signature,
};
use axum::extract::Path;
use axum::{Json, extract::Query, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use email_address::{EmailAddress, Options};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use webauthn_rs_core::proto::COSEAlgorithm;

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

    /// The expiration for when the challenge will no longer be valid.
    #[serde(with = "time::serde::iso8601")]
    pub expiration: OffsetDateTime,
}

#[derive(Serialize)]
/// Data that can be used to add a new passkey to an existing "account".
pub struct AddPasskeyMetadata {
    /// The user that is attempting to log in.
    #[serde(rename = "userId")]
    pub user_id: String,

    /// The registered display name for the user.
    #[serde(rename = "displayName")]
    pub display_name: String,

    /// The authentication challenge ID.
    pub challenge: String,

    /// The origin to use as the `rpId`.
    pub origin: String,

    /// Maps to [pubKeyCredParams](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#pubkeycredparams)
    #[serde(rename = "pubKeyCredParams")]
    pub supported_public_keys: Vec<PublicKeyParam>,

    /// The expiration for when the challenge will no longer be valid.
    #[serde(with = "time::serde::iso8601")]
    pub expiration: OffsetDateTime,
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
    #[allow(dead_code)]
    public_key: String,

    #[serde(rename = "publicKeyAlgorithm")]
    #[allow(dead_code)]
    public_key_algorithm: i32,

    transports: Vec<String>,
}

#[derive(Deserialize)]
pub struct CredentialFetchResponse {
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,

    #[serde(rename = "clientDataJSON")]
    client_data_json: String,

    /// The verification signature.
    signature: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    response: CredentialCreateResponse,
}

#[derive(Deserialize)]
pub struct SignInRequest {
    /// The ID of the passkey used for the signature.
    id: String,

    response: CredentialFetchResponse,
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

    let user = match select_user(email.clone()).await {
        Ok(user) => user,
        Err(err) => {
            println!("Failed to select user from email: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    error: String::from(UNEXPECTED_ERROR),
                }),
            )
                .into_response();
        }
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

    let passkeys: Vec<String> = match user.clone() {
        Some(user) => match select_passkeys(&user).await {
            Ok(response) => response.into_iter().map(|p| p.id).collect(),
            Err(err) => {
                println!("Failed to select passkeys from email: {err}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: String::from(UNEXPECTED_ERROR),
                    }),
                )
                    .into_response();
            }
        },
        None => vec![],
    };

    let user_id = match user {
        Some(user) => user.id,
        None => challenge.id.to_string(),
    };

    Json(LoginMetadata {
        user_id,
        challenge: challenge.id,
        origin: HOST_NAME.to_string(),
        supported_public_keys: fetch_supported_algorithms(),
        expiration: OffsetDateTime::from_unix_timestamp((challenge.expiration / 1000) as i64)
            .unwrap_or_else(|err| {
                println!("Failed to parse challenge expiration: {err}");
                OffsetDateTime::UNIX_EPOCH
            }),
        available_public_keys: passkeys,
    })
    .into_response()
}

/// Initiates adding a new passkey to the authenticated user.
pub async fn initiate_challenge(cookies: CookieJar) -> impl IntoResponse {
    let (cookie, user) = match get_cookie(cookies).await {
        Ok((cookie, user, _)) => (cookie, user),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let challenge = match create_challenge(cookie.sub).await {
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

    Json(AddPasskeyMetadata {
        user_id: user.id,
        display_name: user.display_name,
        challenge: challenge.id,
        origin: HOST_NAME.to_string(),
        supported_public_keys: fetch_supported_algorithms(),
        expiration: OffsetDateTime::from_unix_timestamp((challenge.expiration / 1000) as i64)
            .unwrap_or_else(|err| {
                println!("Failed to parse challenge expiration: {err}");
                OffsetDateTime::UNIX_EPOCH
            }),
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

    let email = match fetch_email(query.clone()) {
        Ok(email) => email,
        Err(error) => {
            return (
                cookies,
                (StatusCode::BAD_REQUEST, Json(ErrorJson { error })).into_response(),
            );
        }
    };

    let display_name = match fetch_display_name(query) {
        Ok(n) => n,
        Err(error) => {
            return (
                cookies,
                (StatusCode::BAD_REQUEST, Json(ErrorJson { error })).into_response(),
            );
        }
    };

    if match select_user(email.clone()).await {
        Ok(response) => response.is_some(),
        Err(err) => {
            println!("Failed to query for existing user: {err}");
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

    // Verifies that the challenge is valid.
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

    // Verifies the rpIdHash
    match parse_authenticator_data(request.response.authenticator_data) {
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

    match insert_passkey(
        challenge,
        attestation_object,
        request.response.transports,
        email.to_string(),
        display_name,
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

/// Authenticates a user with a previously registered passkey.
pub async fn signin(
    cookies: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    Json(request): Json<SignInRequest>,
) -> (CookieJar, impl IntoResponse) {
    let email = match fetch_email(query) {
        Ok(e) => e,
        Err(e) => {
            return (
                cookies,
                (StatusCode::BAD_REQUEST, Json(ErrorJson { error: e })).into_response(),
            );
        }
    };

    let user = match select_user(email.to_string()).await {
        Ok(user) => match user {
            Some(u) => u,
            None => {
                return (
                    cookies,
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorJson {
                            error: String::from("Email is not registered"),
                        }),
                    )
                        .into_response(),
                );
            }
        },
        Err(err) => {
            println!("Error selecting user during sign in: {err}");
            return (
                cookies,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: UNEXPECTED_ERROR.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };

    let client_data = match parse_client_data(request.response.client_data_json, "webauthn.get") {
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

    // Verifies the challenge.
    match redeem_challenge(client_data.challenge.clone(), email.to_string()).await {
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

    let passkey = match select_passkeys(&user).await {
        Ok(passkeys) => match passkeys.iter().find(|p| p.id == request.id) {
            Some(p) => p.clone(),
            None => {
                println!("User with this email does not have passkey that was used");
                return (
                    cookies,
                    (
                        StatusCode::FORBIDDEN,
                        Json(ErrorJson {
                            error: String::from("Invalid passkey"),
                        }),
                    )
                        .into_response(),
                );
            }
        },
        Err(err) => {
            println!("Failed to select passkeys for email: {err}");
            return (
                cookies,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: UNEXPECTED_ERROR.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };

    match update_sign_count(passkey.id.to_string(), authenticator_data.sign_count).await {
        Ok(success) => {
            if !success {
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
        }
        Err(err) => {
            println!("Failed to update passkey sign count: {err}");
            return (
                cookies,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: UNEXPECTED_ERROR.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    }

    match verify_signature(
        passkey,
        &client_data,
        &authenticator_data,
        &request.response.signature,
    ) {
        Ok(_) => {}
        Err(err) => {
            println!("Failed to verify signature: {err}");
            return (
                cookies,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorJson {
                        error: UNEXPECTED_ERROR.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };

    match authenticate(cookies.clone(), email) {
        Ok(c) => (
            c,
            (
                StatusCode::OK,
                Json(ErrorJson {
                    error: UNEXPECTED_ERROR.to_string(),
                }),
            )
                .into_response(),
        ),
        Err(err) => {
            println!("Failed to authenticate: {err}");
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

/// Logs the user out.
pub async fn signout(cookies: CookieJar) -> (CookieJar, impl IntoResponse) {
    (clear(cookies), StatusCode::NO_CONTENT.into_response())
}

/// Adds a new passkey to an existing account.
pub async fn add_passkey(
    cookies: CookieJar,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let (cookie, user) = match get_cookie(cookies).await {
        Ok((cookie, user, _)) => (cookie, user),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // Verifies the rpIdHash
    match parse_authenticator_data(request.response.authenticator_data) {
        Ok(a) => a,
        Err(err) => {
            println!("Failed to parse authenticatorData: {err}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: String::from("Invalid authenticatorData"),
                }),
            )
                .into_response();
        }
    };

    let attestation_object = match parse_attestation_object(request.response.attestation_object) {
        Ok(a) => a,
        Err(err) => {
            println!("Failed to parse attestationObject: {err}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: String::from("Invalid attestationObject"),
                }),
            )
                .into_response();
        }
    };

    let client_data = match parse_client_data(request.response.client_data_json, "webauthn.create")
    {
        Ok(c) => c,
        Err(err) => {
            println!("Failed to parse clientDataJSON: {err}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: String::from("Invalid clientDataJSON"),
                }),
            )
                .into_response();
        }
    };

    // Verifies the challenge.
    let challenge =
        match redeem_challenge(client_data.challenge.clone(), cookie.sub.to_string()).await {
            Ok(c) => c,
            Err(err) => {
                println!("Failed to redeem challenge: {err}");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: String::from("Invalid challenge token"),
                    }),
                )
                    .into_response();
            }
        };

    match insert_passkey(
        challenge,
        attestation_object,
        request.response.transports,
        cookie.sub,
        user.display_name,
    )
    .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(err) => {
            println!("Failed to insert passkey: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    error: UNEXPECTED_ERROR.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Deletes a passkey from the authenticated user.
pub async fn delete_passkey(cookies: CookieJar, Path(id): Path<String>) -> impl IntoResponse {
    let passkeys: Vec<String> = match get_cookie(cookies).await {
        Ok((_, _, passkeys)) => passkeys.iter().map(|p| p.id.to_string()).collect(),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if !passkeys.contains(&id) {
        // Passkey does not belong to authenticated user.
        return StatusCode::FORBIDDEN.into_response();
    }

    if passkeys.len() < 2 {
        // Would leave account without a passkey.
        return StatusCode::FORBIDDEN.into_response();
    }

    match passkey_delete(id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            println!("Failed to delete passkey: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
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

/// Fetches the display name from the query string, and checks to ensure it is only alphanumeric characters.
///
/// Technically doesn't check the same requirements as the frontend. The underscores are unlimited, and can
/// be at the beginning or the end. But we'll allow this "bug" because it's fun for people entering security.
fn fetch_display_name(query: HashMap<String, String>) -> Result<String, String> {
    let display_name = match query.get("displayName") {
        Some(n) => n,
        None => return Err(String::from("Invalid displayName")),
    };

    if display_name
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '_')
    {
        return Err(String::from("Invalid displayName"));
    }

    Ok(display_name.to_string())
}

fn fetch_supported_algorithms() -> Vec<PublicKeyParam> {
    COSEAlgorithm::secure_algs()
        .iter()
        .map(|a| PublicKeyParam {
            alg: *a as i32,
            key_type: String::from(PUBLIC_KEY_TYPE),
        })
        .collect()
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
