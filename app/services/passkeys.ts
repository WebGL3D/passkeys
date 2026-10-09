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

  // The challenge timeout, in milliseconds.
  timeout: number;
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
    challenge,
    origin,
    pubKeyCredParams,
    availablePublicKeys,
    timeout,
  } = await response.json();

  return {
    userId: userId,
    challenge: challenge,
    origin,
    pubKeyCredParams,
    availablePublicKeys: availablePublicKeys,
    timeout,
  };
}

export async function signup(
  email: string,
  publicKey: PublicKeyCredential,
): Promise<void> {
  console.log('Signup', publicKey);
  const response = await fetch(
    `/api/v1/passkeys/signup?${new URLSearchParams({
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
