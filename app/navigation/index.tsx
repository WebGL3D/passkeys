import { AppBar, Box, Toolbar } from '@mui/material';
import NavigationAvatarMenu from './avatar-menu';

export default function Navigation() {
  return (
    <AppBar>
      <Toolbar>
        <Box sx={{ flexGrow: 1 }}></Box>
        <Box sx={{ flexGrow: 0 }}>
          <NavigationAvatarMenu />
        </Box>
      </Toolbar>
    </AppBar>
  );
}
