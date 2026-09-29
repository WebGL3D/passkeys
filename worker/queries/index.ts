// TODO: Can we import this from the SQL file?
const PASSKEYS_CREATE_TABLE = `CREATE TABLE IF NOT EXISTS passkeys(
  /* Maps to https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/id */
  id         TEXT PRIMARY KEY,

  /* A hash of the email address for the user associated with the passkey */
  email_hash TEXT,

  /* The public key PEM that belongs to the passkey */
  public_key TEXT,

  /* How many times the private key has signed a challenge */
  count      INTEGER
);
`;

const PASSKEYS_SELECT_EMAIL_HASH = `SELECT * FROM passkeys WHERE email_hash = ?`;

const QUERIES: { [name: string]: string } = {
  SELECT_PASSKEYS: PASSKEYS_CREATE_TABLE + PASSKEYS_SELECT_EMAIL_HASH,
};

export default QUERIES;
