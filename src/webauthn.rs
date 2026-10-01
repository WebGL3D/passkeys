use crate::env::HOST_NAME;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitflags::bitflags;
use sha2::Digest;
use uuid::Uuid;

bitflags! {
    #[derive(Debug)]
    pub struct AuthenticatorFlags: u8 {
        /// If set, the authenticator validated that the user was present through some Test of User Presence (TUP), such as touching a button on the authenticator.
        const USER_PRESENT = 1 << 0;

        /// If set, the authenticator verified the actual user through a biometric, PIN, or other method.
        const USER_VERIFIED = 1 << 2;

        /// If set, the public key credential source used by the authenticator to generate an assertion is backup-eligible.
        /// This means that it can be backed up in some fashion (for example via cloud or local network sync) and as such may become present on an authenticator other than its generating authenticator.
        ///
        /// Backup-eligible credential sources are therefore also known as multi-device credentials.
        const BACKUP_ELIGIBLE = 1 << 3;

        /// If set, the public key credential source is currently backed up (see `BACKUP_ELIGIBLE` for context).
        const BACKUP_STATE = 1 << 4;

        /// If set, the attested credential data will immediately follow the first 37 bytes of the `authenticatorData`.
        const ATTESTED_CREDENTIAL_DATA_PRESENT = 1 << 6;

        /// If set, extension data is present.
        /// Extension data will follow attested credential data if it is present, or will immediately follow the first 37 bytes of the `authenticatorData` if no attested credential data is present.
        const EXTENSION_DATA_PRESENT = 1 << 7;
    }
}

/// Parsed [authenticatorData](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data)
pub struct AuthenticatorData {
    /// The sha256 hashed bytes of the rpId
    ///
    /// Verified before being returned by `parse_authenticator_data`
    pub rp_id_hash: [u8; 32],

    /// The raw flags byte, from the authenticator data.
    pub flags: AuthenticatorFlags,

    /// The number of times the private key has been used to sign for this credential.
    pub sign_count: u32,

    /// The Authenticator Attestation Globally Unique Identifier, a unique number that identifies the model of the authenticator (not the specific instance of the authenticator).
    /// A relying party can use this to find out the characteristics of the authenticator by looking up its metadata statement via the [FIDO metadata service](https://fidoalliance.org/metadata/).
    ///
    /// This is relevant in certain situations such as enterprise deployments or where regulatory requirements dictate a certain type of authenticator be used; it should be ignored otherwise.
    pub authenticator_attestation_guid: Option<Uuid>,

    /// A unique identifier for this credential so that it can be requested for future authentications.
    ///
    /// Encoded as Base64, URL safe, no padding.
    pub credential_id: Option<String>,

    pub credential_public_key: Option<String>,
}

/// Parses [authenticatorData](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data)
pub fn parse_authenticator_data(authenticator_data: String) -> Result<AuthenticatorData, String> {
    let parsed_data = match URL_SAFE_NO_PAD.decode(authenticator_data) {
        Ok(parsed_data) => parsed_data,
        Err(_) => return Err(String::from("Failed to decode authenticator data.")),
    };

    if parsed_data.len() < 37 {
        return Err(String::from("Invalid authenticator data length."));
    }

    let rp_id_hash: [u8; 32] = match parsed_data[0..32].try_into() {
        Ok(rp_id_hash) => rp_id_hash,
        Err(_) => return Err(String::from("Failed to parse rpIdHash")),
    };

    if !rp_id_hash.eq(sha2::Sha256::digest(HOST_NAME.to_string()).as_slice()) {
        return Err(String::from("rpIdHash did not match expected value"));
    }

    let flags = match AuthenticatorFlags::from_bits(parsed_data[32]) {
        Some(flags) => flags,
        None => return Err(String::from("Failed to parse authenticator flags.")),
    };

    let sign_count = match parsed_data[33..37].try_into() {
        Ok(bytes) => u32::from_be_bytes(bytes),
        Err(_) => return Err(String::from("Failed to parse sign_count")),
    };

    let mut authenticator_attestation_guid: Option<Uuid> = None;
    let mut credential_id: Option<String> = None;
    let mut credential_public_key: Option<String> = None;

    if flags.contains(AuthenticatorFlags::ATTESTED_CREDENTIAL_DATA_PRESENT) {
        let credential_id_start = 55;
        if parsed_data.len() < credential_id_start {
            return Err(String::from(
                "Invalid authenticator data length, for attested credentials present.",
            ));
        }

        authenticator_attestation_guid = Some(match Uuid::from_slice(&parsed_data[37..53]) {
            Ok(uuid) => uuid,
            Err(_) => return Err(String::from("Failed to parse AAGUID")),
        });

        let credential_length = u16::from_be_bytes([parsed_data[53], parsed_data[54]]) as usize;
        let credential_id_end = credential_id_start + credential_length;
        if parsed_data.len() < credential_id_end {
            return Err(String::from(
                "Invalid authenticator data length, for attested credentials.",
            ));
        }

        credential_id =
            Some(URL_SAFE_NO_PAD.encode(&parsed_data[credential_id_start..credential_id_end]));
        println!("credential_id: {:?}", credential_id);

        // TODO: Figure out what to do with this
        let foo: ciborium::Value = match ciborium::from_reader(&parsed_data[credential_id_end..]) {
            Ok(reader) => reader,
            Err(err) => {
                return Err(format!(
                    "Failed to parse (attested) credentials public key: {err}"
                ));
            }
        };
        println!("credential public key: {:?}", foo);
    }

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        authenticator_attestation_guid,
        credential_id,
        credential_public_key,
    })
}
