export type User = {
  emailAddress: string;
};

// Fetches the currently logged in user.
export async function getAuthenticatedUser(): Promise<User | null> {
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

// Updates the "stored" email address for the user.
export async function updateEmail(emailAddress: string): Promise<void> {
  const response = await fetch('/api/v1/users/email', {
    credentials: 'include',
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

  return Promise.resolve();
}
