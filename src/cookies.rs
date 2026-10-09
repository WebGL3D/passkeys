use crate::env::{HOST_NAME, ISSUER, JWT_PRIVATE_KEY, JWT_PUBLIC_KEY};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

const AUTH_COOKIE_NAME: &str = "auth_token";

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCookie {
    /// The email address of the authenticated user.
    pub sub: String,

    /// The cookie expiration.
    pub exp: usize,

    /// The cookie issuer.
    pub iss: String,
}

/// Fetches the authentication details from the cookie jar.
pub fn fetch(cookies: CookieJar) -> Result<AuthCookie, String> {
    let cookie = match cookies.get(AUTH_COOKIE_NAME) {
        Some(cookie) => cookie.value(),
        None => return Err("Authentication cookie is not set".to_string()),
    };

    let public_key = match DecodingKey::from_rsa_pem(JWT_PUBLIC_KEY.as_bytes()) {
        Ok(key) => key,
        Err(e) => return Err(e.to_string()),
    };

    match decode::<AuthCookie>(cookie, &public_key, &Validation::new(Algorithm::RS256)) {
        Ok(auth) => {
            if !auth.claims.iss.eq(ISSUER.as_str()) {
                return Err(String::from("iss mismatch"));
            }

            Ok(auth.claims)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Authenticates the cookie jar with a JWT.
pub fn authenticate(cookies: CookieJar, email: String) -> Result<CookieJar, String> {
    let private_key = match EncodingKey::from_rsa_pem(JWT_PRIVATE_KEY.as_bytes()) {
        Ok(key) => key,
        Err(e) => return Err(e.to_string()),
    };

    let cookie_expiration = time::Duration::days(7);
    match encode(
        &Header::new(Algorithm::RS256),
        &AuthCookie {
            sub: email,
            exp: (Utc::now().timestamp() + cookie_expiration.whole_seconds()) as usize,
            iss: ISSUER.to_string(),
        },
        &private_key,
    ) {
        Ok(token) => {
            let cookie = Cookie::build((AUTH_COOKIE_NAME, token))
                .path("/")
                .max_age(cookie_expiration)
                .secure(!HOST_NAME.eq("localhost"))
                .http_only(true)
                .build();
            Ok(cookies.add(cookie))
        }
        Err(e) => Err(format!("Failed to encode JWT: {}", e)),
    }
}

/// Removes the authentication cookie from the cookie jar.
pub fn clear(cookies: CookieJar) -> CookieJar {
    let cookie = Cookie::build((AUTH_COOKIE_NAME, ""))
        .path("/")
        .max_age(time::Duration::ZERO)
        .build();
    cookies.remove(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear() {
        let cookies = clear(
            CookieJar::new()
                .add(Cookie::new("foo", "bar"))
                .add(Cookie::new("a", "b"))
                .add(Cookie::new(AUTH_COOKIE_NAME, "hello_world")),
        );

        assert_eq!(serialize(cookies, false), "a=b, foo=bar");
    }

    #[test]
    #[should_panic(expected = "JWT__PRIVATE_KEY is not set.")]
    fn test_authenticate_no_jwt_private_key() {
        let _ = authenticate(
            CookieJar::new()
                .add(Cookie::new("foo", "bar"))
                .add(Cookie::new("a", "b")),
            String::from("hello"),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Authentication cookie is not set")]
    fn test_fetch_no_cookie() {
        let cookies = CookieJar::new()
            .add(Cookie::new("foo", "bar"))
            .add(Cookie::new("a", "b"));
        let _ = fetch(cookies).unwrap();
    }

    #[test]
    #[should_panic(expected = "JWT__PUBLIC_KEY is not set.")]
    fn test_fetch_no_jwt_public_key() {
        let cookies = CookieJar::new()
            .add(Cookie::new("foo", "bar"))
            .add(Cookie::new("a", "b"))
            .add(Cookie::new(AUTH_COOKIE_NAME, "fake"));
        let _ = fetch(cookies).unwrap();
    }

    fn serialize(cookies: CookieJar, keys_only: bool) -> String {
        let mut remaining_cookies = cookies
            .iter()
            .map(|c| match keys_only {
                true => c.name().to_string(),
                false => c.to_string(),
            })
            .collect::<Vec<String>>();
        remaining_cookies.sort();
        remaining_cookies.join(", ")
    }
}
