import { Fragment, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { LoadingState } from '../constants';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';

export default function Home() {
  const [authenticatedUser, loadingState] = useAuthenticatedUser();
  const navigate = useNavigate();

  useEffect(() => {
    if (loadingState !== LoadingState.Success) {
      return;
    }

    if (authenticatedUser) {
      navigate('/settings');
    } else {
      navigate('/login');
    }
  }, [navigate, authenticatedUser, loadingState]);

  return <Fragment />;
}
