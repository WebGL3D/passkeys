import { Alert } from '@mui/material';

export default function Error() {
  return (
    <Alert severity="error">
      Something went wrong we were not expecting. Please refresh the page.
    </Alert>
  );
}
