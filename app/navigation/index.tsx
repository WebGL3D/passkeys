import {
  AppBar,
  Avatar,
  Box,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Toolbar,
} from '@mui/material';
import { Fragment, useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';
import { signOut } from '../services/passkeys';

export default function Navigation() {
  const [authenticatedUser] = useAuthenticatedUser();
  const [menuOpen, setMenuOpen] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const location = useLocation();

  useEffect(() => {
    // Close the menu if the authenticated user changes, or we navigate to a new page.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMenuOpen(false);
  }, [authenticatedUser, location]);

  return (
    <AppBar>
      <Toolbar>
        <Box sx={{ flexGrow: 1 }}></Box>
        <Box sx={{ flexGrow: 0 }}>
          {authenticatedUser ? (
            <Fragment>
              <IconButton
                onClick={(e) => {
                  setMenuAnchor(e.currentTarget);
                  setMenuOpen(true);
                }}
              >
                <Avatar src={authenticatedUser.avatar}>
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
          ) : (
            <Button>
              <NavLink style={{ all: 'unset' }} to="/login">
                Log In (Demo)
              </NavLink>
            </Button>
          )}
        </Box>
      </Toolbar>
    </AppBar>
  );
}
