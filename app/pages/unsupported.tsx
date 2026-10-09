import { Alert } from '@mui/material';

export default function Unsupported() {
  return (
    <Alert severity="error">
      Passkeys are not supported on this browser or device.
    </Alert>
  );
}
