import { Avatar, Button, IconButton, Menu, MenuItem } from '@mui/material';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { NavLink, useLocation } from 'react-router';
import { LoadingState } from '../constants';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';
import { signOut } from '../services/passkeys';

export default function NavigationAvatarMenu() {
  const [authenticatedUser, loadingState] = useAuthenticatedUser();
  const [menuOpen, setMenuOpen] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [avatarLoadError, setAvatarLoadError] = useState(false);
  const location = useLocation();
  const avatarIcon = useMemo(() => {
    if (avatarLoadError || !authenticatedUser) {
      return '';
    }

    return authenticatedUser.avatar;
  }, [avatarLoadError, authenticatedUser]);

  useEffect(() => {
    // Close the menu if the authenticated user changes, or we navigate to a new page.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMenuOpen(false);
  }, [authenticatedUser, location]);

  useEffect(() => {
    // If the authenticated user changes, we'll reset the avatar load error state.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setAvatarLoadError(false);
  }, [authenticatedUser]);

  if (loadingState === LoadingState.Loading) {
    return <Fragment />;
  }

  if (!authenticatedUser) {
    return (
      <Button>
        <NavLink style={{ all: 'unset' }} to="/login">
          Log In (Demo)
        </NavLink>
      </Button>
    );
  }

  return (
    <Fragment>
      <IconButton
        onClick={(e) => {
          setMenuAnchor(e.currentTarget);
          setMenuOpen(true);
        }}
      >
        <Avatar src={avatarIcon} onError={() => setAvatarLoadError(true)}>
          {authenticatedUser.emailAddress.charAt(0)}
        </Avatar>
      </IconButton>
      <Menu
        anchorEl={menuAnchor}
        open={menuOpen}
        onClose={() => setMenuOpen(false)}
      >
        <MenuItem>
          <NavLink style={{ all: 'unset' }} to="/settings">
            Settings
          </NavLink>
        </MenuItem>
        <MenuItem onClick={signOut}>Log Out</MenuItem>
      </Menu>
    </Fragment>
  );
}
