import { CircularProgress } from '@mui/material';
import { BrowserRouter, Route, Routes } from 'react-router';
import { LoadingState } from '../constants';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';
import Navigation from '../navigation';
import Error from './error';
import Home from './home';
import Login from './login';
import Settings from './settings';
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

  return (
    <BrowserRouter>
      <Navigation />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </BrowserRouter>
  );
}
