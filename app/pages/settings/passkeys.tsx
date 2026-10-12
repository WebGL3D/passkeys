import { Alert, Box, Button, Paper, Typography } from '@mui/material';
import { Fragment, useEffect, useState } from 'react';
import useAuthenticatedUser from '../../hooks/useAuthenticatedUser';
import {
  addPasskey,
  createCredential,
  initiateAddPasskey,
} from '../../services/passkeys';
import { getPasskeys, type Passkey } from '../../services/users';
import PasskeyIcon from './passkey-icon';
import './passkeys.scss';

export default function Passkeys() {
  const [authenticatedUser] = useAuthenticatedUser();
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [refreshCount, setRefreshCount] = useState(0);
  const [debounce, setDebounce] = useState(false);
  const [errorText, setErrorText] = useState('');

  const addPasskeyClicked = async () => {
    if (!authenticatedUser) {
      return;
    }

    setDebounce(true);
    const emailAddress = authenticatedUser.emailAddress;

    try {
      const {
        challenge,
        pubKeyCredParams,
        userId,
        displayName,
        origin,
        expiration,
      } = await initiateAddPasskey();
      const credential = await createCredential(
        {
          id: userId,
          displayName,
          name: emailAddress,
        },
        challenge,
        expiration,
        origin,
        pubKeyCredParams,
      );

      await addPasskey(credential);
      setRefreshCount(refreshCount + 1);
    } catch (err) {
      console.error('Failed to add alternative passkey', err);
      setErrorText(`Failed to add alternative passkey: ${err}`);
      setTimeout(() => {
        setErrorText('');
      }, 5000);
    }
  };

  useEffect(() => {
    if (!authenticatedUser) {
      return;
    }

    getPasskeys()
      .then((p) => {
        setErrorText('');
        setPasskeys(p);
        console.log(p);
      })
      .catch((err) => {
        setErrorText(`${err}`);
      })
      .finally(() => {
        setDebounce(false);
      });
  }, [authenticatedUser, refreshCount]);

  return (
    <Fragment>
      <Typography variant="h5" component="h2" sx={{ mt: 2 }}>
        Passkeys
      </Typography>
      {errorText && <Alert severity="error">{errorText}</Alert>}
      {passkeys.map((passkey) => {
        return (
          <Paper
            className="passkey-row"
            sx={{ p: 1, display: 'flex', flexDirection: 'row', mb: 1 }}
          >
            <PasskeyIcon passkey={passkey} />
            <Box sx={{ flexGrow: 1, pl: 1 }}>
              <Typography
                variant="subtitle1"
                sx={{
                  opacity: 0.65,
                  fontSize: '8pt',
                }}
              >
                Credential ID: {passkey.id}
                <br />
                Authenticator Attestation GUID: {passkey.aaguid}
                <br />
                Registered: {passkey.created.toLocaleDateString()} (last used:{' '}
                {passkey.lastUsed.toLocaleDateString()})
              </Typography>
            </Box>
          </Paper>
        );
      })}
      {passkeys.length > 0 && (
        <Button
          onClick={addPasskeyClicked}
          disabled={debounce}
          fullWidth
          variant="contained"
        >
          Add Alternate Passkey
        </Button>
      )}
    </Fragment>
  );
}
