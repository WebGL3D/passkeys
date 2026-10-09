import { useEffect, useState } from 'react';
import { LoadingState } from '../constants';
import {
  AuthenticatedUserChanged,
  getAuthenticatedUser,
  type User,
} from '../services/users';

export default function useAuthenticatedUser(): [
  User | null | undefined,
  LoadingState,
] {
  const [authenticatedUser, setAuthenticatedUser] = useState<
    User | null | undefined
  >(undefined);
  const [loadingState, setLoadingState] = useState(LoadingState.Loading);

  const refresh = () => {
    getAuthenticatedUser()
      .then((user) => {
        setAuthenticatedUser(user);
        setLoadingState(LoadingState.Success);
      })
      .catch((err) => {
        console.error('Failed to check authenticated user', err);
        setLoadingState(LoadingState.Error);
      });
  };

  useEffect(() => {
    AuthenticatedUserChanged.addEventListener('changed', refresh);
    refresh();

    return () => {
      AuthenticatedUserChanged.removeEventListener('changed', refresh);
    };
  }, []);

  return [authenticatedUser, loadingState];
}
