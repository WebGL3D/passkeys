import { env } from 'cloudflare:workers';

// TODO: Can we import this from the SQL file?
const PASSKEYS_CREATE_TABLE = `CREATE TABLE IF NOT EXISTS passkeys(
  /* Maps to https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/id */
  id         TEXT PRIMARY KEY,

  /* A hash of the email address for the user associated with the passkey */
  email_hash TEXT,

  /* The public key PEM that belongs to the passkey */
  public_key TEXT,

  /* The algorithm for the public key */
  public_key_algorithm INTEGER,

  /* How many times the private key has signed a challenge */
  sign_count INTEGER DEFAULT(0),

  /* A timestamp for when the passkey was created */
  created    INTEGER DEFAULT(unixepoch('subsec') * 1000),

  /* A timestamp for when the passkey was last updated (effectively, used) */
  updated    INTEGER DEFAULT(unixepoch('subsec') * 1000)
);
`;

const CHALLENGES_CREATE_TABLE = `CREATE TABLE IF NOT EXISTS challenges(
    /* The challenge token itself */
    id         TEXT PRIMARY KEY,

    /* The hash of the email address the challenge belongs to */
    email_hash TEXT,

    /* A timestamp for when the challenge will expire */
    expiration    INTEGER DEFAULT((unixepoch('subsec') * 1000) + ${Number(env.CHALLENGE_EXPIRATION_SECONDS) * 1000})
);

/* Cleanup old challenges */
DELETE FROM challenges WHERE expiration < (unixepoch('subsec') * 1000);
`;

const PASSKEYS_SELECT_EMAIL_HASH = `SELECT * FROM passkeys WHERE [email_hash] = ?`;
const PASSKEYS_INSERT = `INSERT INTO passkeys ([id], [email_hash], [public_key], [public_key_algorithm]) VALUES (?, ?, ?, ?) RETURNING *`;
const PASSKEYS_UPDATE_EMAIL_HASH = `UPDATE passkeys SET
  [email_hash] = ?,
  [updated] = unixepoch('subsec') * 1000
WHERE [email_hash] = ?
RETURNING *`;
const PASSKEYS_UPDATE_SIGN_COUNT = `UPDATE passkeys SET
  [sign_count] = ?,
  [updated] = unixepoch('subsec') * 1000
WHERE [id] = ?
AND [sign_count] < ?
RETURNING *`;
const CHALLENGES_INSERT = `INSERT INTO challenges ([id], [email_hash]) VALUES (?, ?) RETURNING *`;
const CHALLENGES_REDEEM = `DELETE FROM challenges WHERE [id] = ? RETURNING *`;

const QUERIES: { [name: string]: string } = {
  PASSKEYS_SELECT: PASSKEYS_CREATE_TABLE + PASSKEYS_SELECT_EMAIL_HASH,
  PASSKEYS_INSERT: PASSKEYS_CREATE_TABLE + PASSKEYS_INSERT,
  PASSKEYS_UPDATE_EMAIL_HASH:
    PASSKEYS_CREATE_TABLE + PASSKEYS_UPDATE_EMAIL_HASH,
  PASSKEYS_UPDATE_SIGN_COUNT:
    PASSKEYS_CREATE_TABLE + PASSKEYS_UPDATE_SIGN_COUNT,
  CHALLENGES_INSERT: CHALLENGES_CREATE_TABLE + CHALLENGES_INSERT,
  CHALLENGES_REDEEM: CHALLENGES_CREATE_TABLE + CHALLENGES_REDEEM,
};

export default QUERIES;
