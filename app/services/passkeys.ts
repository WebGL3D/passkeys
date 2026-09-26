type InitiateLoginResponse = {
  // The user found when initiating the login.
  user: PublicKeyCredentialUserEntityJSON;
};

export async function initiateLogin(
  email: string,
): Promise<InitiateLoginResponse> {
  const response = await fetch(
    `/api/v1/passkeys/initiate-login?${new URLSearchParams({
      email,
    })}`,
  );

  if (response.ok) {
    return await response.json();
  }

  return Promise.reject(`Failed to initiate login: ${response.status}`);
}
