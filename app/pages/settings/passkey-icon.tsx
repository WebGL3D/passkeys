import {
  Android,
  Apple,
  Key,
  Microsoft,
  SettingsRemote,
} from '@mui/icons-material';
import type { Passkey } from '../../services/users';

type PasskeyIconInput = {
  passkey: Passkey;
};

export default function PasskeyIcon({ passkey }: PasskeyIconInput) {
  switch (passkey.format) {
    case 'apple':
      return <Apple />;
    case 'android-key':
    case 'android-safetynet':
      return <Android />;
    case 'fido-u2f':
    case 'packed':
      return <SettingsRemote />;
    case 'tpm':
      return <Microsoft />;
    default:
      // Options for the future: Fingerprint, Devices / Cloud (Backup enabled?), Bluetooth?
      return <Key />;
  }
}
