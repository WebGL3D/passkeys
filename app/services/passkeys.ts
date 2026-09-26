type InitiateLoginResponse = {
  // The user found when initiating the login.
  user: PublicKeyCredentialUserEntity;
  origin: string;
  challenge: ArrayBuffer;
};

function base64ToBuffer(base64: string): ArrayBuffer {
  const { buffer } = Uint8Array.from(base64);
  return buffer;
}

export async function initiateLogin(
  email: string,
): Promise<InitiateLoginResponse> {
  const response = await fetch(
    `/api/v1/passkeys/initiate-login?${new URLSearchParams({
      email,
    })}`,
  );

  if (!response.ok) {
    return Promise.reject(`Failed to initiate login: ${response.status}`);
  }

  const { user, challenge, origin } = await response.json();
  return {
    user: {
      id: base64ToBuffer(user.id),
      name: user.name,
      displayName: user.displayName,
    },
    challenge: base64ToBuffer(challenge),
    origin,
  };
}
