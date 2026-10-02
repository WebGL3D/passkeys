use crate::webauthn::AttestationObject;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Error;
use serde::{Deserialize, de::DeserializeOwned};
use sha2::Digest;
use uuid::Uuid;

/// The passkey record from the database.
#[derive(Deserialize, Clone)]
pub struct Passkey {
    /// Maps to [PublicKeyCredential.id](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/id)
    pub id: String,

    /// The public key PEM that belongs to the passkey.
    pub public_key: String,

    /// The algorithm for the `public_key`.
    pub public_key_algorithm: i32,

    /// A hash of the email address for the user associated with the passkey.
    pub email_hash: String,

    /// How many times the private key has signed a challenge.
    pub sign_count: u32,

    /// The milliseconds after epoch when the passkey was registered.
    pub created: u64,
}

/// The challenge record from the database.
#[derive(Deserialize, Clone)]
pub struct Challenge {
    /// The challenge token.
    pub id: String,

    /// A hash of the email address the challenge can be redeemed for.
    pub email_hash: String,

    /// The milliseconds after epoch when the challenge will expire.
    pub expiration: u64,
}

/// Executes a database query by its name, with a list of arguments.
pub async fn db1_query<T: DeserializeOwned>(
    name: &str,
    args: Vec<String>,
) -> Result<Vec<T>, reqwest::Error> {
    let query_string = if args.len() > 0 {
        format!("&arg={}", args.join("&arg="))
    } else {
        String::from("")
    };

    match reqwest::get(format!(
        "http://d1.webgl3d.dev/query?name={name}{query_string}"
    ))
    .await
    {
        Ok(response) => response.json::<Vec<T>>().await,
        Err(error) => Err(error),
    }
}

/// Selects all passkeys associated with an email address.
pub async fn select_passkeys(email: String) -> Result<Vec<Passkey>, Error> {
    db1_query::<Passkey>("PASSKEYS_SELECT", vec![hash_email(email)]).await
}

/// Starts a challenge for the email address.
pub async fn create_challenge(email: String) -> Result<Challenge, String> {
    let id = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
    match db1_query::<Challenge>("CHALLENGES_INSERT", vec![id, hash_email(email)]).await {
        Ok(challenges) => match challenges.first() {
            Some(challenge) => Ok(challenge.clone()),
            None => Err(String::from("No challenge was returned from insert query.")),
        },
        Err(_) => Err(String::from("Failed to insert challenge into database.")),
    }
}

/// Redeems a challenge token.
pub async fn redeem_challenge(id: String, email: String) -> Result<Challenge, String> {
    match db1_query::<Challenge>("CHALLENGES_REDEEM", vec![id]).await {
        Ok(challenges) => match challenges.first() {
            Some(challenge) => {
                if challenge.email_hash != hash_email(email) {
                    return Err(String::from("Email did not match challenge"));
                }

                Ok(challenge.clone())
            }

            None => Err(String::from("No challenge was returned from redeem query.")),
        },
        Err(err) => Err(format!("Failed to redeem challenge from database: {err}")),
    }
}

/// Inserts a passkey into the database.
pub async fn insert_passkey(
    attestation_object: AttestationObject,
    public_key: String,
    public_key_algorithm: i32,
    email: String,
) -> Result<Passkey, String> {
    let credential_id = match attestation_object.authenticator_data.credential_id {
        Some(c) => c,
        None => return Err(String::from("Invalid credential ID")),
    };

    // TODO: Read from here, instead of having the value passed in.
    /*
    let credential_public_key = match attestation_object.authenticator_data.credential_public_key {
        Some(k) => k,
        None => return Err(String::from("Invalid credential public key")),
    };
    // */

    match db1_query::<Passkey>(
        "PASSKEYS_INSERT",
        vec![
            credential_id,
            hash_email(email),
            public_key,
            public_key_algorithm.to_string(),
        ],
    )
    .await
    {
        Ok(passkeys) => match passkeys.first() {
            Some(passkey) => Ok(passkey.clone()),
            None => Err(String::from("No passkey was returned from insert query.")),
        },
        Err(err) => Err(format!("Failed to insert passkey into database: {err}")),
    }
}

/// Updates the email address (hashes) stored in the passkeys table.
pub async fn update_email(
    original_email: String,
    new_email: String,
) -> Result<Vec<Passkey>, String> {
    match db1_query::<Passkey>(
        "PASSKEYS_UPDATE_EMAIL_HASH",
        vec![hash_email(original_email), hash_email(new_email)],
    )
    .await
    {
        Ok(updated_passkeys) => Ok(updated_passkeys),
        Err(err) => Err(format!("Failed to update database: {err}")),
    }
}

/// Deletes all data about a user, by their email address.
pub async fn delete_user(email: String) -> Result<Vec<Passkey>, String> {
    match db1_query::<Passkey>("USERS_DELETE", vec![hash_email(email)]).await {
        Ok(passkeys) => Ok(passkeys),
        Err(err) => Err(format!("Failed to delete user from database: {err}")),
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
    #[case("vapid@webgl3d.dev", "c9ca94190f3d5ef771f63acce3644c15")]
    fn test_hash_email(#[case] email: String, #[case] expected: String) {
        assert_eq!(hash_email(email), expected);
    }
}
