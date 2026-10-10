import { Box } from '@mui/material';
import { Fragment, useEffect } from 'react';
import { useNavigate } from 'react-router';
import useAuthenticatedUser from '../../hooks/useAuthenticatedUser';
import AccountSettings from './account-settings';

export default function Settings() {
  const [authenticatedUser] = useAuthenticatedUser();
  const navigate = useNavigate();

  useEffect(() => {
    if (authenticatedUser === null) {
      navigate('/login');
    }
  }, [navigate, authenticatedUser]);

  if (!authenticatedUser) {
    return <Fragment />;
  }

  return (
    <Box sx={{ maxWidth: '500px', margin: 'auto' }}>
      <AccountSettings />
    </Box>
  );
}
