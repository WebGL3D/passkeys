import { EditSquare } from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  Collapse,
  FormGroup,
  Link,
  Paper,
  TextField,
  Typography,
  type AlertColor,
} from '@mui/material';
import { Fragment, useState } from 'react';
import { isEmail, isEmpty } from 'validator';
import useAuthenticatedUser from '../../hooks/useAuthenticatedUser';
import { updateEmail } from '../../services/users';
import './account-settings.scss';

export default function AccountSettings() {
  const [proposedEmail, setProposedEmail] = useState('');
  const [updatingEmail, setUpdatingEmail] = useState(false);
  const [alertSeverity, setAlertSeverity] = useState<AlertColor>('info');
  const [alertText, setAlertText] = useState('');
  const [authenticatedUser] = useAuthenticatedUser();

  const emailUpdated = (email: string) => {
    if (
      isEmpty(email) ||
      !isEmail(email) ||
      email === authenticatedUser?.emailAddress
    ) {
      setProposedEmail('');
      return;
    }

    setProposedEmail(email);
  };

  const changeEmail = async () => {
    if (!proposedEmail || updatingEmail) {
      return;
    }

    setUpdatingEmail(true);

    try {
      await updateEmail(proposedEmail);
      setProposedEmail('');
      setAlertSeverity('success');
      setAlertText('Successfully updated email address');
    } catch (e) {
      setAlertSeverity('error');
      setAlertText(`${e}`);
    } finally {
      setTimeout(() => {
        setUpdatingEmail(false);
        setAlertText('');
      }, 5_000);
    }
  };

  const submit = async (key: string) => {
    if (key === 'Enter') {
      await changeEmail();
    }
  };

  if (!authenticatedUser) {
    return <Fragment />;
  }

  return (
    <Fragment>
      <Typography variant="h4" component="h1">
        Account Settings
      </Typography>
      <Collapse in={!!alertText}>
        <Alert severity={alertSeverity} sx={{ mt: 1, mb: 1 }}>
          {alertText}
        </Alert>
      </Collapse>
      <Paper sx={{ p: 1 }}>
        <FormGroup sx={{ display: 'flex', flexDirection: 'row' }}>
          <Box
            sx={{
              mr: 1,
              height: '48px',
              width: '48px',
              backgroundImage: `url(${authenticatedUser.avatar})`,
              backgroundSize: '100%',
            }}
          >
            <Link href="https://gravatar.com/profile/avatars" target="_blank">
              <Button
                id="edit-avatar"
                sx={{ minWidth: 0, p: 1, width: '100%', height: '100%' }}
              >
                <EditSquare />
              </Button>
            </Link>
          </Box>
          <TextField
            sx={{ flexGrow: 1 }}
            defaultValue={authenticatedUser.emailAddress}
            disabled={updatingEmail}
            onChange={({ currentTarget }) => emailUpdated(currentTarget.value)}
            onKeyDown={({ key }) => submit(key)}
            type="email"
            label="Email Address"
            variant="standard"
          />
          <Button
            variant="outlined"
            disabled={updatingEmail || !proposedEmail}
            sx={{ flexGrow: 0, ml: 1 }}
            onClick={changeEmail}
            size="small"
          >
            Change Email
          </Button>
        </FormGroup>
        <Typography
          variant="caption"
          sx={{
            lineHeight: '11pt',
            display: 'inline-block',
            mt: 1,
            opacity: 0.65,
          }}
        >
          Updating your email address here will not update the name stored with
          your passkey authenticator. This only changes the email you sign in
          with.
          <br />
          Maybe in the future?{' '}
          <Link href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalCurrentUserDetails_static">
            PublicKeyCredential.signalCurrentUserDetails
          </Link>
        </Typography>
      </Paper>
    </Fragment>
  );
}
