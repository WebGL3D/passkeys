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
import { Fragment, useState } from 'react';
import { NavLink } from 'react-router';
import useAuthenticatedUser from '../hooks/useAuthenticatedUser';
import { signOut } from '../services/passkeys';

export default function Navigation() {
  const [authenticatedUser] = useAuthenticatedUser();
  const [menuOpen, setMenuOpen] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);

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
                <MenuItem
                  onClick={() => {
                    setMenuOpen(false);
                    signOut();
                  }}
                >
                  Log Out
                </MenuItem>
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
