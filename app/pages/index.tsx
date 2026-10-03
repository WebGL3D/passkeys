import { CircularProgress } from '@mui/material';
import { LoadingState } from '../constants';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';
import Error from './error';
import Login from './login';
import Unsupported from './unsupported';

export default function AppContent() {
  const [authenticatedUser, loadingState] = useAuthenticatedUser();

  if (!navigator.credentials) {
    return <Unsupported />;
  }

  if (loadingState === LoadingState.Error) {
    return <Error />;
  }

  if (authenticatedUser === null && loadingState === LoadingState.Loading) {
    return <CircularProgress />;
  }

  return <Login />;
}
