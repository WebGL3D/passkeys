import { clearCache } from './users';

type InitiateLoginResponse = {
  // The user ID to create the passkey with.
  userId: string;

  // The origin the passkey will be saved under.
  origin: string;

  // The challenge to submit back to the server, with the passkey.
  challenge: string;

  // The supported public key credential types.
  pubKeyCredParams: PublicKeyCredentialParameters[];

  // The IDs of the public keys the user can login with.
  availablePublicKeys: string[];

  // The challenge expiration.
  expiration: Date;
};

type InitiateLoginRawResponse = {
  // The user ID to create the passkey with.
  userId: string;

  // The origin the passkey will be saved under.
  origin: string;

  // The challenge to submit back to the server, with the passkey.
  challenge: string;

  // The supported public key credential types.
  pubKeyCredParams: PublicKeyCredentialParameters[];

  // The IDs of the public keys the user can login with.
  availablePublicKeys: string[];

  // The challenge expiration.
  expiration: string;
};

type InitiateAddPasskeyRawResponse = {
  // The user ID to create the passkey with.
  userId: string;

  displayName: string;

  // The origin the passkey will be saved under.
  origin: string;

  // The challenge to submit back to the server, with the passkey.
  challenge: string;

  // The supported public key credential types.
  pubKeyCredParams: PublicKeyCredentialParameters[];

  // The challenge expiration.
  expiration: string;
};

type InitiateAddPasskeyResponse = {
  // The user ID to create the passkey with.
  userId: string;

  displayName: string;

  // The origin the passkey will be saved under.
  origin: string;

  // The challenge to submit back to the server, with the passkey.
  challenge: string;

  // The supported public key credential types.
  pubKeyCredParams: PublicKeyCredentialParameters[];

  // The challenge expiration.
  expiration: Date;
};

export async function initiateLogin(
  email: string,
): Promise<InitiateLoginResponse> {
  const response = await fetch(
    `/api/v1/passkeys/initiate-login?${new URLSearchParams({
      email,
    })}`,
    {
      credentials: 'include',
    },
  );

  if (!response.ok) {
    return Promise.reject(`Failed to initiate login: ${response.status}`);
  }

  const {
    userId,
    origin,
    pubKeyCredParams,
    availablePublicKeys,
    challenge,
    expiration,
  }: InitiateLoginRawResponse = await response.json();

  return {
    userId,
    challenge,
    origin,
    availablePublicKeys,
    pubKeyCredParams,
    expiration: new Date(expiration),
  };
}

// Fetches the details needed to add a new passkey to an existing "account".
export async function initiateAddPasskey(): Promise<InitiateAddPasskeyResponse> {
  const response = await fetch('/api/v1/passkeys', {
    credentials: 'include',
  });

  if (!response.ok) {
    return Promise.reject(
      `Failed to initiate adding a passkey: ${response.status}`,
    );
  }

  const {
    userId,
    displayName,
    origin,
    pubKeyCredParams,
    challenge,
    expiration,
  }: InitiateAddPasskeyRawResponse = await response.json();

  return {
    userId,
    displayName,
    challenge,
    origin,
    pubKeyCredParams,
    expiration: new Date(expiration),
  };
}

export async function signup(
  email: string,
  displayName: string,
  publicKey: PublicKeyCredential,
): Promise<void> {
  console.log('Signup', publicKey);
  const response = await fetch(
    `/api/v1/passkeys/signup?${new URLSearchParams({
      email,
      displayName,
    })}`,
    {
      credentials: 'include',
      method: 'POST',
      body: JSON.stringify(publicKey.toJSON()),
      headers: {
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    return Promise.reject(`Failed to register passkey: ${response.status}`);
  }

  clearCache();
}

export async function signin(email: string, publicKey: PublicKeyCredential) {
  console.log('Signin', publicKey);
  const response = await fetch(
    `/api/v1/passkeys/signin?${new URLSearchParams({
      email,
    })}`,
    {
      credentials: 'include',
      method: 'POST',
      body: JSON.stringify(publicKey.toJSON()),
      headers: {
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    return Promise.reject(`Failed to sign in with passkey: ${response.status}`);
  }

  clearCache();
}

export async function signOut(): Promise<void> {
  const response = await fetch('/api/v1/passkeys/signout', {
    credentials: 'include',
    method: 'POST',
  });

  clearCache();

  if (response.ok) {
    return;
  }

  return Promise.reject(`Failed to sign out: ${response.status}`);
}

export async function addPasskey(
  publicKey: PublicKeyCredential,
): Promise<void> {
  console.log('Adding passkey', publicKey);
  const response = await fetch('/api/v1/passkeys', {
    credentials: 'include',
    method: 'POST',
    body: JSON.stringify(publicKey.toJSON()),
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    return Promise.reject(`Failed to register passkey: ${response.status}`);
  }

  clearCache();
}

// Saves a passkey with the device/authenticator.
export async function createCredential(
  user: PublicKeyCredentialUserEntityJSON,
  challenge: string,
  challengeExpiration: Date,
  origin: string,
  pubKeyCredParams: PublicKeyCredentialParameters[],
): Promise<PublicKeyCredential> {
  const request = PublicKeyCredential.parseCreationOptionsFromJSON({
    user,
    challenge,
    rp: {
      id: origin,
      name: 'Passkeys Demo',
    },
    authenticatorSelection: {
      // This will require biometrics before saving the passkey.
      userVerification: 'required',
    },
    pubKeyCredParams,
    timeout: challengeExpiration.getTime() - +new Date(),

    // Not supported by all authenticators, and could default to 'none' anyway if it's not supported.
    attestation: 'none',
  });

  console.log('Creating public key credential', request);

  const credential = (await navigator.credentials.create({
    publicKey: request,
  })) as PublicKeyCredential;

  console.log('Registered public key', credential);

  return credential;
}
