import { Alert, Box, Button, Input } from '@mui/material';
import { useState } from 'react';
import { isEmail, isEmpty } from 'validator';
import { initiateLogin } from '../services/passkeys';

const enterKey = 'Enter';

export default function Login() {
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [emailValid, setEmailValid] = useState(true);

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

  const login = async () => {
    if (email) {
      setError('');
      const response = await initiateLogin(email);
      console.log(response);
    } else {
      setError('Please enter a valid email before logging in.');
    }
  };

  const submitEmail = async (key: string) => {
    if (!email) {
      return;
    }

    if (key === enterKey) {
      await login();
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
      <Input
        type="email"
        error={!emailValid}
        onChange={({ currentTarget }) => emailUpdated(currentTarget.value)}
        onKeyDown={({ key }) => submitEmail(key)}
        autoComplete="email webauthn"
        fullWidth
      />
      <Button
        type="button"
        variant="contained"
        size="large"
        onClick={() => submitEmail(enterKey)}
        disabled={!email}
        sx={{ mt: 1 }}
        fullWidth
      >
        Log In
      </Button>
    </Box>
  );
}
