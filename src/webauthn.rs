use crate::db::Passkey;
use crate::env::{HOST_NAME, ORIGIN};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, digest::Output};
use uuid::Uuid;
use webauthn_rs_core::proto::COSEKey;

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
    /// The decoded bytes of the authenticator data.
    pub raw_bytes: Vec<u8>,

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

    /// The base64 (url) encoded public key credential.
    ///
    /// This can be parsed into a `COSEKey`.
    pub credential_public_key: Option<String>,

    /// The algorithm used in the public key credential.
    pub credential_public_key_algorithm: Option<i32>,
}

/// TODO: This is missing the attestation statement (attStmt).
pub struct AttestationObject {
    /// A text string that indicates the format of the attestation statement.
    ///
    /// # Examples
    /// Common Values:
    /// - `none`
    /// - `packed`
    /// - `tpm`
    /// - `android-key`
    /// - `android-safetynet`
    /// - `fido-u2f`
    ///
    /// # Notes
    /// For passkeys that are synced between devices (e.g. Apple/iCloud), the attestation format will always be `none`.
    ///
    /// See also: [Defined Attestation Statement Formats](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats), [IANA Registry](https://w3c.github.io/webauthn/#sctn-att-fmt-reg)
    pub format: String,

    /// The authenticator data, parsed from the attestation object.
    pub authenticator_data: AuthenticatorData,
}

/// Maps to [AuthenticatorResponse.clientDataJSON](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON)
#[derive(Serialize, Deserialize)]
pub struct ClientData {
    /// A SHA256 hash of the clientDataJSON, for signature verification.
    #[serde(skip_serializing, skip_deserializing)]
    pub hash: Option<Output<Sha256>>,

    /// `webauthn.create` OR `webauthn.get`
    #[serde(rename = "type")]
    pub authn_type: String,

    /// The challenge token.
    pub challenge: String,

    /// The origin the passkey was created on.
    pub origin: String,
}

/// The (raw) parsed [attestationObject](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject).
#[derive(Debug, Deserialize)]
struct InternalAttestationObject {
    #[serde(rename = "authData")]
    auth_data: serde_cbor_2::Value,

    fmt: String,

    #[serde(rename = "attStmt")]
    att_stmt: serde_cbor_2::Value,
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

    if !rp_id_hash.eq(Sha256::digest(HOST_NAME.to_string()).as_slice()) {
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
    let mut credential_public_key_algorithm: Option<i32> = None;

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

        let credential_value: serde_cbor_2::Value =
            match serde_cbor_2::from_reader(&parsed_data[credential_id_end..]) {
                Ok(reader) => reader,
                Err(err) => {
                    return Err(format!(
                        "Failed to parse (attested) credentials public key: {err}"
                    ));
                }
            };

        let encoded_key = match credential_value {
            serde_cbor_2::Value::Bytes(bytes) => URL_SAFE_NO_PAD.encode(bytes),
            _ => return Err(String::from("Failed to decode COSE key")),
        };

        match parse_cose_key(encoded_key.to_string()) {
            Ok(cose_key) => {
                credential_public_key_algorithm = Some(cose_key.type_ as i32);
            }
            Err(err) => return Err(format!("Failed to parse COSE key: {err}")),
        };

        credential_public_key = Some(encoded_key);
    }

    Ok(AuthenticatorData {
        raw_bytes: parsed_data,
        rp_id_hash,
        flags,
        sign_count,
        authenticator_attestation_guid,
        credential_id,
        credential_public_key,
        credential_public_key_algorithm,
    })
}

/// Parses [attestationObject](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject)
pub fn parse_attestation_object(attestation_object: String) -> Result<AttestationObject, String> {
    let parsed_data = match URL_SAFE_NO_PAD.decode(attestation_object) {
        Ok(parsed_data) => {
            serde_cbor_2::from_reader::<InternalAttestationObject, &[u8]>(parsed_data.as_slice())
        }
        Err(err) => return Err(format!("Failed to decode attestation object: {err}")),
    };

    let attestation_map = match parsed_data {
        Ok(a) => a,
        Err(err) => return Err(format!("Failed to parse attestation object: {err}")),
    };

    let authenticator_data = match attestation_map.auth_data {
        serde_cbor_2::Value::Bytes(auth_data) => {
            parse_authenticator_data(URL_SAFE_NO_PAD.encode(auth_data.as_slice()))
        }
        _ => return Err(String::from("Failed to translate attestation authData")),
    };

    Ok(AttestationObject {
        format: attestation_map.fmt,
        authenticator_data: match authenticator_data {
            Ok(a) => a,
            Err(err) => return Err(format!("Failed to decode authData: {err}")),
        },
    })
}

/// Parses [clientDataJSON](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON)
pub fn parse_client_data(
    client_data_json: String,
    expected_type: &str,
) -> Result<ClientData, String> {
    let json_bytes = match URL_SAFE_NO_PAD.decode(client_data_json) {
        Ok(json_bytes) => json_bytes,
        Err(_) => return Err(String::from("Failed base64 decode")),
    };

    let json = match String::from_utf8(json_bytes.clone()) {
        Ok(json) => serde_json::from_str::<ClientData>(json.as_str()),
        Err(_) => return Err(String::from("Failed String::from_utf8")),
    };

    match json {
        Ok(mut client_data) => {
            if client_data.authn_type == "webauthn.get" {
                client_data.hash = Some(Sha256::digest(json_bytes));
            } else {
                client_data.hash = None;
            }

            if !client_data.authn_type.eq(expected_type) {
                return Err(String::from("authn type did not match"));
            }

            if !client_data.origin.eq(ORIGIN.as_str().trim_end_matches("/")) {
                return Err(String::from("origin did not match"));
            }

            Ok(client_data)
        }
        Err(_) => Err(String::from("serde_json::from_str")),
    }
}

/// Verifies the signature for a passkey.
pub fn verify_signature(
    passkey: Passkey,
    client_data: &ClientData,
    authenticator_data: &AuthenticatorData,
    signature: &str,
) -> Result<bool, String> {
    let signature_bytes = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(signature_bytes) => signature_bytes,
        Err(_) => return Err(String::from("Failed to decode signature")),
    };

    let verification_data = match client_data.hash {
        Some(hash) => {
            let mut result = Vec::with_capacity(hash.len() + authenticator_data.raw_bytes.len());
            result.extend_from_slice(&authenticator_data.raw_bytes);
            result.extend_from_slice(&hash);
            result
        }
        None => return Err(String::from("No clientDataJSON hash to verify.")),
    };

    let public_key = match parse_cose_key(passkey.public_key) {
        Ok(public_key) => public_key,
        Err(err) => return Err(err),
    };

    match public_key.verify_signature(&signature_bytes, &verification_data) {
        Ok(success) => {
            if success {
                Ok(true)
            } else {
                Err(String::from("Signature verification failed"))
            }
        }
        Err(err) => Err(format!("Failed to verify signature: {err}")),
    }
}

/// Parses the `COSEKey` from a base64 (url) encoded string.
fn parse_cose_key(encoded_key: String) -> Result<COSEKey, String> {
    match URL_SAFE_NO_PAD.decode(encoded_key) {
        Ok(public_key) => {
            let cose_key: serde_cbor_2::Value =
                match serde_cbor_2::from_reader(public_key.as_slice()) {
                    Ok(cose_key) => cose_key,
                    Err(err) => return Err(format!("Failed to parse encoded COSE key: {err}")),
                };

            match COSEKey::try_from(&cose_key) {
                Ok(cose_key) => Ok(cose_key),
                Err(err) => Err(format!("Failed to translate COSE key: {err}")),
            }
        }
        Err(err) => Err(format!("Failed to parse public key: {err}")),
    }
}
