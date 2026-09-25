import { Box, Button } from '@mui/material';

export default function Login() {
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
      }}
    >
      <Button type="button" variant="contained" size="large">
        Log In
      </Button>
    </Box>
  );
}
