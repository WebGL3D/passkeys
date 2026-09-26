import { Alert, Box, Button, Collapse, TextField } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { isAlphanumeric, isEmail, isEmpty } from 'validator';
import { initiateLogin, signup } from '../services/passkeys';

const enterKey = 'Enter';

// Obviously this validation existing in the frontend doesn't actually do anything
// to anyone that cares, and is easily bypassed.
// But as this is a demo, this is fine.
function isDisplayNameValid(name: string): boolean {
  const startsWith = /^[\s_]+/;
  if (startsWith.test(name)) {
    return false;
  }

  const endsWith = /[\s_]+$/;
  if (endsWith.test(name)) {
    return false;
  }

  const multiple = /[\s_]{2,}/;
  if (multiple.test(name)) {
    return false;
  }

  return isAlphanumeric(name, 'en-US', { ignore: /[ _]/ });
}

export default function Login() {
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [emailValid, setEmailValid] = useState(true);
  const [displayNameValid, setDisplayNameValid] = useState(true);
  const [validatingEmail, setValidatingEmail] = useState(false);
  const [requestDisplayName, setRequestDisplayName] = useState(false);
  const [userId, setUserId] = useState<string>('');
  const [challenge, setChallenge] = useState<string>('');
  const [authenticationTimeout, setAuthenticationTimeout] = useState(0);
  const [pubKeyCredParams, setPubKeyCredParams] = useState<
    PublicKeyCredentialParameters[]
  >([]);
  const [origin, setOrigin] = useState<string>('');
  const displayNameRef = useRef<HTMLInputElement>(null);

  const clearChallenge = () => {
    setChallenge('');
    setUserId('');
    setRequestDisplayName(false);
    setAuthenticationTimeout(0);
    setPubKeyCredParams([]);
    setOrigin('');
  };

  useEffect(() => {
    if (authenticationTimeout < 1 || !challenge) {
      return;
    }

    const timeout = setTimeout(() => {
      // Challenge has expired.
      clearChallenge();

      // Clear the display name
      if (displayNameRef.current) {
        displayNameRef.current.blur();
        setDisplayName('');
        displayNameRef.current.value = '';
      }
    }, authenticationTimeout);

    return () => clearTimeout(timeout);
  }, [challenge, authenticationTimeout]);

  const emailUpdated = (newEmail: string) => {
    if (isEmpty(newEmail, { ignore_whitespace: true })) {
      setEmail('');
      setEmailValid(true);
      return;
    }

    const isValid = isEmail(newEmail, { allow_utf8_local_part: false });
    if (isValid) {
      setEmail(newEmail);
    } else {
      setEmail('');
    }

    setEmailValid(isValid);
  };

  const displayNameUpdated = (newDisplayName: string) => {
    if (isEmpty(newDisplayName, { ignore_whitespace: true })) {
      setDisplayName('');
      setDisplayNameValid(true);
      return;
    }

    const isValid = isDisplayNameValid(newDisplayName);
    if (isValid) {
      setDisplayName(newDisplayName);
    } else {
      setDisplayName('');
    }

    setDisplayNameValid(isValid);
  };

  const attemptLogin = async () => {
    if (!email) {
      return;
    }

    setValidatingEmail(true);

    try {
      const response = await initiateLogin(email);
      setChallenge(response.challenge);
      setPubKeyCredParams(response.pubKeyCredParams);
      setAuthenticationTimeout(response.timeout);
      setOrigin(response.origin);
      setUserId(response.userId);

      if (response.availablePublicKeys.length > 0) {
        // User is registered, let's attempt to fetch their credentials.
        const request = PublicKeyCredential.parseRequestOptionsFromJSON({
          rpId: response.origin,
          challenge: response.challenge,
          allowCredentials: response.availablePublicKeys.map((keyId) => {
            return {
              id: keyId,
              type: 'public-key',
            };
          }),
        });
        const credentials = await navigator.credentials.get({
          mediation: 'required',
          publicKey: request,
        });
        console.log('Credentials', credentials);
      } else {
        // User has not signed up yet, let's prompt them to input a display name.
        setRequestDisplayName(true);
      }
    } finally {
      setValidatingEmail(false);
    }
  };

  const attemptSignup = async () => {
    if (!userId || !challenge || !displayName) {
      return;
    }

    try {
      // Clear the challenge, so the timeout stops, and the dispaly name input becomes disabled.
      setChallenge('');

      // Create the passkey on the device.
      const request = PublicKeyCredential.parseCreationOptionsFromJSON({
        user: {
          id: userId,
          name: email,
          displayName,
        },
        rp: {
          id: origin,
          name: 'Passkeys Demo',
        },
        authenticatorSelection: {
          // This will require biometrics before saving the passkey.
          // userVerification: 'required',
        },
        challenge,
        pubKeyCredParams,
        attestation: 'direct',
        timeout: authenticationTimeout,
      });
      const credentials = (await navigator.credentials.create({
        publicKey: request,
      })) as PublicKeyCredential;

      if (credentials) {
        await signup(email, credentials);
        // TODO: Sign in the user
      }
    } catch (e) {
      console.error('Failed to create passkey', e);
      clearChallenge();
      setError('Failed to create passkey, please try again.');
    }
  };

  const submit = async (key: string) => {
    if (!email) {
      return;
    }

    if (key === enterKey) {
      if (requestDisplayName) {
        // If we're requesting a display name, attempt signup instead.
        await attemptSignup();
      } else {
        await attemptLogin();
      }
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        height: '100vh',
        maxWidth: '300px',
        margin: 'auto',
        p: 2,
      }}
    >
      {error && <Alert severity="error">{error}</Alert>}
      <TextField
        id="email"
        type="email"
        label="Email Address"
        variant="standard"
        error={!emailValid}
        onChange={({ currentTarget }) => emailUpdated(currentTarget.value)}
        onKeyDown={({ key }) => submit(key)}
        autoComplete="email webauthn"
        disabled={validatingEmail || requestDisplayName}
        fullWidth
      />
      <Collapse
        in={requestDisplayName}
        sx={{ width: '100%' }}
        addEndListener={() => displayNameRef.current?.focus()}
      >
        <TextField
          required
          variant="standard"
          label="Display Name"
          type="text"
          error={!displayNameValid}
          sx={{ mt: 1 }}
          onChange={({ currentTarget }) =>
            displayNameUpdated(currentTarget.value)
          }
          onKeyDown={({ key }) => submit(key)}
          disabled={!challenge}
          inputRef={displayNameRef}
          autoComplete="username name"
          slotProps={{ htmlInput: { maxLength: 20 } }}
          fullWidth
        />
      </Collapse>
      <Button
        type="button"
        variant="contained"
        size="large"
        onClick={() => submit(enterKey)}
        disabled={
          !email || validatingEmail || (requestDisplayName && !challenge)
        }
        sx={{ mt: 1 }}
        fullWidth
      >
        {requestDisplayName ? 'Sign Up' : 'Log In OR Sign Up'}
      </Button>
    </Box>
  );
}
