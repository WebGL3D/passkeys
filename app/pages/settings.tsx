import { Fragment, useEffect } from 'react';
import { useNavigate } from 'react-router';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';

export default function Settings() {
  const [authenticatedUser] = useAuthenticatedUser();
  const navigate = useNavigate();

  useEffect(() => {
    if (!authenticatedUser) {
      navigate('/login');
    }
  }, [navigate, authenticatedUser]);

  return <Fragment />;
}
