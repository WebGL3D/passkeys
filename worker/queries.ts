import { env } from 'cloudflare:workers';

// TODO: Can we import this from the SQL file?
/* Passkeys */
const PASSKEYS_CREATE_TABLE = `CREATE TABLE IF NOT EXISTS passkeys(
  /* Maps to https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/id */
  id         TEXT PRIMARY KEY,

  /* The ID of the user that the passkey belongs to */
  user_id TEXT,

  /* The public key PEM that belongs to the passkey */
  public_key TEXT,

  /* The algorithm for the public key */
  public_key_algorithm INTEGER,

  /* The format of the passkey at initial attestation */
  format TEXT,

  /* The Authenticator Attestation Globally Unique Identifier */
  aaguid TEXT,

  /* How many times the private key has signed a challenge */
  sign_count INTEGER DEFAULT(0),

  /* A timestamp for when the passkey was created */
  created    INTEGER DEFAULT(unixepoch('subsec') * 1000),

  /* A timestamp for when the passkey record was last modified */
  updated    INTEGER DEFAULT(unixepoch('subsec') * 1000),

  /* A timestamp for when the passkey was last used for authentication */
  last_used  INTEGER DEFAULT(unixepoch('subsec') * 1000)
);
`;

const PASSKEYS_SELECT_USER_ID = `SELECT * FROM passkeys WHERE [user_id] = ?`;
const PASSKEYS_INSERT = `INSERT INTO passkeys ([id], [user_id], [public_key], [public_key_algorithm], [format], [aaguid]) VALUES (?, ?, ?, ?, ?, ?) RETURNING *`;
const PASSKEYS_UPDATE_SIGN_COUNT = `UPDATE passkeys SET
  [sign_count] = ?,
  [updated] = unixepoch('subsec') * 1000,
  [last_used] = unixepoch('subsec') * 1000
WHERE [id] = ?
AND [sign_count] < ?
RETURNING *`;
const PASSKEYS_UPDATE_LAST_USED = `UPDATE passkeys SET
  [updated] = unixepoch('subsec') * 1000,
  [last_used] = unixepoch('subsec') * 1000
WHERE [id] = ?
RETURNING *`;
const PASSKEYS_DELETE = `DELETE FROM passkeys WHERE [id] = ? RETURNING *`;

/* Challenges */
const CHALLENGES_CREATE_TABLE = `CREATE TABLE IF NOT EXISTS challenges(
    /* The challenge token itself */
    id         TEXT PRIMARY KEY,

    /* The hash of the email address the challenge belongs to */
    email_hash TEXT NOT NULL,

    /* A timestamp for when the challenge will expire */
    expiration    INTEGER DEFAULT((unixepoch('subsec') * 1000) + ${Number(env.CHALLENGE_EXPIRATION_SECONDS) * 1000})
);

/* Cleanup old challenges */
DELETE FROM challenges WHERE expiration < (unixepoch('subsec') * 1000);
`;

const CHALLENGES_INSERT = `INSERT INTO challenges ([id], [email_hash]) VALUES (?, ?) RETURNING *`;
const CHALLENGES_REDEEM = `DELETE FROM challenges WHERE [id] = ? RETURNING *`;

/* Users */
const USERS_CREATE_TABLE = `CREATE TABLE IF NOT EXISTS users(
    /* The ID of the user */
    id         TEXT PRIMARY KEY,

    /* The display name the user has chosen */
    display_name TEXT NOT NULL,

    /* The hash of the email address for the user */
    email_hash TEXT NOT NULL UNIQUE,

    /* A timestamp for when the challenge will expire */
    created    INTEGER DEFAULT(unixepoch('subsec') * 1000),

    /* A timestamp for when the user record was last modified */
    updated    INTEGER DEFAULT(unixepoch('subsec') * 1000)
);
`;

const USERS_SELECT_EMAIL_HASH = `SELECT * FROM users WHERE [email_hash] = ?`;
const USERS_INSERT = `INSERT INTO users ([id], [display_name], [email_hash]) VALUES (?, ?, ?) RETURNING *`;
const USERS_UPDATE_EMAIL_HASH = `UPDATE users SET
  [email_hash] = ?,
  [updated] = unixepoch('subsec') * 1000
WHERE [email_hash] = ?
RETURNING *`;
const USERS_DELETE = `DELETE FROM challenges WHERE [email_hash] = ?;
DELETE FROM passkeys WHERE [user_id] = (SELECT [id] FROM users WHERE [email_hash] = ?);
DELETE FROM users WHERE [email_hash] = ? RETURNING *`;

const QUERIES: { [name: string]: string } = {
  /* Passkeys */
  PASSKEYS_SELECT_USER_ID: PASSKEYS_CREATE_TABLE + PASSKEYS_SELECT_USER_ID,
  PASSKEYS_INSERT: PASSKEYS_CREATE_TABLE + PASSKEYS_INSERT,
  PASSKEYS_UPDATE_SIGN_COUNT:
    PASSKEYS_CREATE_TABLE + PASSKEYS_UPDATE_SIGN_COUNT,
  PASSKEYS_UPDATE_LAST_USED: PASSKEYS_CREATE_TABLE + PASSKEYS_UPDATE_LAST_USED,
  PASSKEYS_DELETE: PASSKEYS_CREATE_TABLE + PASSKEYS_DELETE,

  /* Challenges */
  CHALLENGES_INSERT: CHALLENGES_CREATE_TABLE + CHALLENGES_INSERT,
  CHALLENGES_REDEEM: CHALLENGES_CREATE_TABLE + CHALLENGES_REDEEM,

  /* Users */
  USERS_SELECT_EMAIL_HASH: USERS_CREATE_TABLE + USERS_SELECT_EMAIL_HASH,
  USERS_INSERT: USERS_CREATE_TABLE + USERS_INSERT,
  USERS_UPDATE_EMAIL_HASH: USERS_CREATE_TABLE + USERS_UPDATE_EMAIL_HASH,
  USERS_DELETE:
    CHALLENGES_CREATE_TABLE +
    PASSKEYS_CREATE_TABLE +
    USERS_CREATE_TABLE +
    USERS_DELETE,
};

export default QUERIES;
