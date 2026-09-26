import Login from './login';
import Unsupported from './unsupported';

export default function AppContent() {
  if (!navigator.credentials) {
    return <Unsupported />;
  }

  return <Login />;
}
