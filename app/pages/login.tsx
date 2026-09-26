import { Box, Button, Collapse, TextField } from '@mui/material';
import { useRef, useState } from 'react';
import { isAlphanumeric, isEmail, isEmpty } from 'validator';
import { initiateLogin } from '../services/passkeys';

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
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [emailValid, setEmailValid] = useState(true);
  const [displayNameValid, setDisplayNameValid] = useState(true);
  const [validatingEmail, setValidatingEmail] = useState(false);
  const [requestDisplayName, setRequestDisplayName] = useState(false);
  const [userId, setUserId] = useState<BufferSource>();
  const [challenge, setChallenge] = useState<ArrayBuffer>();
  const [origin, setOrigin] = useState<string>('');
  const displayNameRef = useRef<HTMLInputElement>(null);

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
      setOrigin(response.origin);
      setUserId(response.user.id);

      if (response.user.displayName) {
        // User is registered, let's attempt to fetch their credentials.
        const credentials = await navigator.credentials.get({
          mediation: 'required',
          publicKey: {
            rpId: response.origin,
            challenge: response.challenge,
          },
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

    const credentials = await navigator.credentials.create({
      publicKey: {
        user: {
          id: userId,
          name: email,
          displayName,
        },
        rp: {
          id: origin,
          name: 'Passkeys Demo',
        },
        challenge,
        // These are the recommended algorithms: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#pubkeycredparams
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -257 },
        ],
      },
    });
    console.log('Credentials', credentials);
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
        disabled={!email || validatingEmail}
        sx={{ mt: 1 }}
        fullWidth
      >
        {requestDisplayName ? 'Sign Up' : 'Log In OR Sign Up'}
      </Button>
    </Box>
  );
}
