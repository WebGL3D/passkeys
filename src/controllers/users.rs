use crate::cookies::{authenticate, clear, fetch, get_cookie};
use crate::db::{delete_user, update_email as db1_update_email};
use crate::webauthn::AuthenticatorFlags;
use axum::{Json, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use email_address::{EmailAddress, Options};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize)]
struct User {
    /// The email address of the user.
    #[serde(rename = "emailAddress")]
    email_address: String,

    /// The chosen display name for the user.
    display_name: String,

    /// The user's avatar icon/image URL.
    avatar: String,
}

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    /// The new email address to set.
    #[serde(rename = "emailAddress")]
    email_address: String,
}

/// Information about a stored passkey.
#[derive(Serialize)]
pub struct Passkey {
    /// The credential ID.
    pub id: String,

    /// How many times the passkey has signed a credential.
    ///
    /// zero if the authenticator does not support this.
    #[serde(rename = "signCount")]
    pub sign_count: u32,

    /// The Authenticator Attestation Globally Unique Identifier.
    pub aaguid: String,

    /// The format of the passkey at initial attestation.
    pub format: String,

    /// The flags the passkey was created with.
    pub flags: Vec<String>,

    /// The transports the passkey was created with.
    pub transports: Vec<String>,

    /// The timestamp the passkey was last used for authentication.
    #[serde(with = "time::serde::iso8601", rename = "lastUsed")]
    pub last_used: OffsetDateTime,

    /// The timestamp the passkey was last updated.
    #[serde(with = "time::serde::iso8601")]
    pub updated: OffsetDateTime,

    /// The timestamp the passkey was created.
    #[serde(with = "time::serde::iso8601")]
    pub created: OffsetDateTime,
}

/// Fetches the currently authenticated user.
pub async fn authenticated_user(cookies: CookieJar) -> (CookieJar, impl IntoResponse) {
    match get_cookie(cookies.clone()).await {
        Ok((cookie, user, _)) => {
            let gravatar_hash = md5::compute(cookie.sub.to_lowercase());
            (
                cookies,
                Json(User {
                    email_address: cookie.sub,
                    display_name: user.display_name,
                    avatar: format!(
                        "https://www.gravatar.com/avatar/{:x}?size=150",
                        gravatar_hash
                    ),
                })
                .into_response(),
            )
        }
        Err(err) => {
            println!("{err}");
            (clear(cookies), StatusCode::UNAUTHORIZED.into_response())
        }
    }
}

/// Updates the email address associated with the current user.
pub async fn update_email(
    cookies: CookieJar,
    Json(body): Json<UpdateEmailRequest>,
) -> (CookieJar, impl IntoResponse) {
    let original_email = match fetch(cookies.clone()) {
        Ok(user) => user.sub,
        Err(_) => return (cookies, StatusCode::UNAUTHORIZED.into_response()),
    };

    let new_email = match EmailAddress::parse_with_options(
        body.email_address.as_str(),
        Options::default()
            .without_domain_literal()
            .without_display_text()
            .with_required_tld(),
    ) {
        Ok(email) => email.email(),
        Err(_) => return (cookies, StatusCode::BAD_REQUEST.into_response()),
    };

    match db1_update_email(new_email.to_string(), original_email).await {
        Ok(passkeys) => {
            println!("Updated {} passkeys with new email address", passkeys.len());
            match authenticate(cookies.clone(), new_email) {
                Ok(c) => (c, StatusCode::NO_CONTENT.into_response()),
                Err(err) => {
                    println!("Failed to authenticate after email update: {err}");
                    (cookies, StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
            }
        }
        Err(err) => {
            println!("Failed to update passkeys with new email address: {err}");
            (cookies, StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Deletes a user "account", i.e. all of their stored passkeys.
pub async fn delete_account(cookies: CookieJar) -> (CookieJar, impl IntoResponse) {
    let email = match fetch(cookies.clone()) {
        Ok(user) => user.sub,
        Err(_) => return (cookies, StatusCode::UNAUTHORIZED.into_response()),
    };

    match delete_user(email).await {
        Ok(user) => {
            match user {
                Some(user) => {
                    println!("Deleted user: {}", user.id);
                }
                None => {
                    println!("No user to delete");
                }
            }

            (clear(cookies), StatusCode::NO_CONTENT.into_response())
        }
        Err(err) => {
            println!("Failed to delete user: {err}");
            (cookies, StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Fetches all passkeys associated with the authenticated user.
pub async fn fetch_passkeys(cookies: CookieJar) -> impl IntoResponse {
    let passkeys = match get_cookie(cookies).await {
        Ok((_, _, passkeys)) => passkeys,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let results: Vec<Passkey> =
        passkeys
            .iter()
            .map(|p| Passkey {
                id: p.id.to_string(),
                aaguid: p.aaguid.to_string(),
                format: p.format.to_string(),
                flags: match AuthenticatorFlags::from_bits(p.flags) {
                    Some(flags) => flags.iter_names().map(|(n, _)| n.to_string()).collect(),
                    None => vec![],
                },
                transports: p.transports.split(",").map(|t| t.to_string()).collect(),
                sign_count: p.sign_count,
                last_used: OffsetDateTime::from_unix_timestamp((p.last_used / 1000) as i64)
                    .unwrap_or_else(|err| {
                        println!(
                            "Failed to translate last used date for passkey ({}): {}",
                            p.last_used, err
                        );
                        OffsetDateTime::UNIX_EPOCH
                    }),
                updated: OffsetDateTime::from_unix_timestamp((p.updated / 1000) as i64)
                    .unwrap_or_else(|err| {
                        println!(
                            "Failed to translate updated date for passkey ({}): {}",
                            p.updated, err
                        );
                        OffsetDateTime::UNIX_EPOCH
                    }),
                created: OffsetDateTime::from_unix_timestamp((p.created / 1000) as i64)
                    .unwrap_or_else(|err| {
                        println!(
                            "Failed to translate created date for passkey ({}): {}",
                            p.created, err
                        );
                        OffsetDateTime::UNIX_EPOCH
                    }),
            })
            .collect();

    Json(results).into_response()
}
