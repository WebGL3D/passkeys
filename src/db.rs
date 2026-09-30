use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Error;
use serde::{Deserialize, de::DeserializeOwned};
use sha2::Digest;
use uuid::Uuid;

/// The passkey record from the database.
#[derive(Deserialize)]
pub struct Passkey {
    /// Maps to [PublicKeyCredential.id](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/id)
    pub id: String,

    /// The public key PEM that belongs to the passkey.
    pub public_key: String,

    /// A hash of the email address for the user associated with the passkey.
    pub email_hash: String,

    /// How many times the private key has signed a challenge.
    pub count: i32,
}

/// The challenge record from the database.
#[derive(Deserialize)]
pub struct Challenge {
    /// The challenge token.
    pub id: String,

    /// A hash of the email address the challenge can be redeemed for.
    pub email_hash: String,

    /// The seconds after epoch when the challenge will expire.
    pub expiration: i64,
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
            Some(challenge) => Ok(Challenge {
                // TODO: Is there a better way to do this, maybe with clone()?
                id: challenge.id.to_string(),
                email_hash: challenge.email_hash.to_string(),
                expiration: challenge.expiration,
            }),
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
                if challenge.email_hash != hash_email(email) {}
                Ok(Challenge {
                    // TODO: Is there a better way to do this, maybe with clone()?
                    id: challenge.id.to_string(),
                    email_hash: challenge.email_hash.to_string(),
                    expiration: challenge.expiration,
                })
            }

            None => Err(String::from("No challenge was returned from redeem query.")),
        },
        Err(_) => Err(String::from("Failed to redeem challenge from database.")),
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
