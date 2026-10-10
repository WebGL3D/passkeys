let cachedUser: Promise<User | null> | undefined = undefined;
export const AuthenticatedUserChanged = new EventTarget();

export type User = {
  emailAddress: string;
  avatar: string;
};

type SerializedPasskey = {
  id: string;
  format: string;
  aaguid: string;
  signCount: number;
  lastUsed: string;
  created: string;
  updated: string;
};

export type Passkey = {
  id: string;
  format: string;
  aaguid: string;
  signCount: number;
  lastUsed: Date;
  created: Date;
  updated: Date;
};

async function loadAuthenticatedUser(): Promise<User | null> {
  const response = await fetch('/api/v1/users/authenticated', {
    credentials: 'include',
  });

  if (response.status === 401) {
    return null;
  }

  if (!response.ok) {
    return Promise.reject('Failed to check if user is already logged in.');
  }

  return response.json();
}

// Fetches the currently logged in user.
export function getAuthenticatedUser(): Promise<User | null> {
  if (cachedUser) {
    return cachedUser;
  }

  return (cachedUser = loadAuthenticatedUser().then((user) => {
    console.log('user changed', user);
    AuthenticatedUserChanged.dispatchEvent(new Event('changed'));
    return user;
  }));
}

// Clears the cache, so we can fetch the authenticated user again.
export function clearCache() {
  cachedUser = undefined;
  AuthenticatedUserChanged.dispatchEvent(new Event('changed'));
}

// Updates the "stored" email address for the user.
export async function updateEmail(emailAddress: string): Promise<void> {
  const response = await fetch('/api/v1/users/email', {
    credentials: 'include',
    method: 'POST',
    body: JSON.stringify({ emailAddress }),
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    return Promise.reject(
      `Failed to update email address - error code: ${response.status}`,
    );
  }

  clearCache();
  return Promise.resolve();
}

// Deletes the currently authenticated user "account".
export async function deleteAccount(): Promise<void> {
  const response = await fetch('/api/v1/users/authenticated', {
    credentials: 'include',
    method: 'DELETE',
  });

  if (!response.ok) {
    return Promise.reject(
      `Failed to update email address - error code: ${response.status}`,
    );
  }

  cachedUser = Promise.resolve(null);
  AuthenticatedUserChanged.dispatchEvent(new Event('changed'));
  return Promise.resolve();
}

// Selects all of the passkeys associated with the authenticated user.
export async function getPasskeys(): Promise<Passkey[]> {
  const response = await fetch('/api/v1/users/authenticated/passkeys', {
    credentials: 'include',
  });

  if (!response.ok) {
    return Promise.reject(
      `Failed to fetch passkeys - error code: ${response.status}`,
    );
  }

  const result: SerializedPasskey[] = await response.json();
  return result.map(
    ({ id, aaguid, format, signCount, lastUsed, created, updated }) => {
      return {
        id,
        aaguid,
        format,
        signCount,
        lastUsed: new Date(lastUsed),
        created: new Date(created),
        updated: new Date(updated),
      };
    },
  );
}
