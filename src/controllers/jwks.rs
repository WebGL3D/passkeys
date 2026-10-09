use crate::env::{ISSUER, JWT_PUBLIC_KEY};
use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

/// Specified by [openid.net](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
///
/// Most required fields are omitted, because this application does not actually implement OpenID.
#[derive(Serialize)]
pub struct OpenIdConfiguration {
    /// The JWT `iss` field.
    pub issuer: String,

    /// The endpoint where the JWKS can be found.
    pub jwks_uri: String,
}

/// The result model for the .well-known/jwks endpoint.
#[derive(Serialize)]
pub struct Jwks {
    /// The list of public JSON web (public) keys.
    pub keys: Vec<Jwk>,
}

/// A JSON web key, as defined by [RFC 7517](https://www.rfc-editor.org/info/rfc7517).
#[derive(Serialize)]
pub struct Jwk {
    /// **REQUIRED**
    ///
    /// The JSON web algorithm key type.
    /// Examples: `RSA`, `EC`, `oct`
    ///
    /// See also: [RFC 7518](https://www.rfc-editor.org/info/rfc7518/#section-6.1)
    #[serde(rename = "kty")]
    pub key_type: String,

    /// **OPTIONAL**
    ///
    /// The intended use of the JWK.
    #[serde(rename = "use")]
    pub intended_use: String,

    /// **OPTIONAL**
    ///
    /// The algorithm intended for use with the key.
    pub alg: String,

    /// `n` is the modulus common to both public and private key
    ///
    /// See also: [RSA_get0_key](https://docs.openssl.org/master/man3/RSA_get0_key/#synopsis)
    pub n: String,

    /// `e` is the public exponent (and `d` is the private exponent)
    ///
    /// See also: [RSA_get0_key](https://docs.openssl.org/master/man3/RSA_get0_key/#synopsis)
    pub e: String,
}

/// The .well-known/openid-configuration endpoint.
///
/// This application doesn't expose OpenID connect, but this endpoint will be loaded by jwt.io automatically.
/// This allows for verification/inspection of the JWT returned in the cookie, for educational purposes.
pub async fn openid_configuration() -> impl IntoResponse {
    Json(OpenIdConfiguration {
        issuer: ISSUER.to_string(),
        jwks_uri: format!("{}/.well-known/jwks.json", ISSUER.to_string()),
    })
}

/// The .well-known/jwks.json endpoint - used for signature verification of the JWT.
///
/// While the JWT exclusively used by the server, this endpoint exists as an example (and for self educational purposes).
pub async fn jwks() -> impl IntoResponse {
    match load_public_key(JWT_PUBLIC_KEY.as_bytes()) {
        Ok(key) => Json(Jwks { keys: vec![key] }).into_response(),
        Err(err) => {
            println!("Failed to load JWKS public key: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn load_public_key(public_key_bytes: &[u8]) -> Result<Jwk, String> {
    let public_key = match openssl::rsa::Rsa::public_key_from_pem(public_key_bytes) {
        Ok(key) => key,
        Err(err) => return Err(format!("{err}")),
    };

    Ok(Jwk {
        key_type: "RSA".to_string(),
        intended_use: "sig".to_string(),
        alg: "RS256".to_string(),
        n: URL_SAFE_NO_PAD.encode(public_key.n().to_vec()),
        e: URL_SAFE_NO_PAD.encode(public_key.e().to_vec()),
    })
}
