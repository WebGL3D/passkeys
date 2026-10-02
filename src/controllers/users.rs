use crate::cookies::{authenticate, clear, fetch};
use crate::db::{delete_user, update_email as db1_update_email};
use axum::{Json, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use email_address::{EmailAddress, Options};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct User {
    /// The email address of the user.
    #[serde(rename = "emailAddress")]
    email_address: String,
}

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    /// The new email address to set.
    #[serde(rename = "emailAddress")]
    email_address: String,
}

/// Fetches the currently authenticated user.
pub async fn authenticated_user(cookies: CookieJar) -> impl IntoResponse {
    match fetch(cookies) {
        Ok(user) => Json(User {
            email_address: user.sub,
        })
        .into_response(),
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
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

    match db1_update_email(original_email, new_email.to_string()).await {
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
        Ok(passkeys) => {
            println!("Deleted user with {} passkeys", passkeys.len());
            (clear(cookies), StatusCode::NO_CONTENT.into_response())
        }
        Err(err) => {
            println!("Failed to delete user: {err}");
            (cookies, StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}
