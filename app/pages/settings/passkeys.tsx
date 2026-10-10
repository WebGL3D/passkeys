import { Alert, Box, Paper, Typography } from '@mui/material';
import { Fragment, useEffect, useState } from 'react';
import useAuthenticatedUser from '../../hooks/useAuthenticatedUser';
import { getPasskeys, type Passkey } from '../../services/users';
import PasskeyIcon from './passkey-icon';
import './passkeys.scss';

export default function Passkeys() {
  const [authenticatedUser] = useAuthenticatedUser();
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [errorText, setErrorText] = useState('');

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
      });
  }, [authenticatedUser]);

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
                sx={{ opacity: 0.65, fontSize: '8pt' }}
              >
                Credential ID: {passkey.id}
                <br />
                Authenticator Attestation GUID: {passkey.aaguid}
                <br />
                Registered: {passkey.created.toLocaleDateString()}
              </Typography>
            </Box>
          </Paper>
        );
      })}
    </Fragment>
  );
}
