CREATE TABLE IF NOT EXISTS passkeys(
  /* Maps to https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/id */
  id         TEXT PRIMARY KEY,

  /* A hash of the email address for the user associated with the passkey */
  email_hash TEXT,

  /* The public key PEM that belongs to the passkey */
  public_key TEXT,

  /* How many times the private key has signed a challenge */
  count      INTEGER
);
