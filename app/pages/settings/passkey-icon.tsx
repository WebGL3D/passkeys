import {
  Android,
  Apple,
  Cloud,
  Devices,
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
      if (passkey.transports.includes('usb')) {
        return <SettingsRemote />;
      }

      if (passkey.flags.includes('ACTIVELY_BACKED_UP')) {
        return <Cloud />;
      }

      if (passkey.flags.includes('BACKUP_ELIGIBLE')) {
        return <Devices />;
      }

      // Options for the future: Fingerprint, Bluetooth?
      return <Key />;
  }
}
