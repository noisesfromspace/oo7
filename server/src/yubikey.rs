//! YubiKey PIV-based master key wrapping and unwrapping.
//!
//! The keyring master key is a random 32-byte value. It is wrapped (encrypted)
//! with a P-256 key held in a YubiKey PIV slot, so it can only be recovered by
//! performing ECDH with the card's private key — which happens on-card and is
//! gated behind the key's touch policy. The scheme mirrors age-plugin-yubikey's
//! "piv-p256": wrap uses software ECDH against the card's public key, unwrap
//! uses on-card ECDH via the PIV "decrypt" (key agreement) instruction.
//!
//! The PIV key is generated with PIN policy "never" and touch policy "always",
//! so unlocking the keyring requires a physical touch but no PIN — suitable for
//! headless daemon startup on an auto-login session.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use yubikey::{
    Context, YubiKey,
    certificate::{Certificate, PublicKeyInfo},
    piv::{AlgorithmId, RetiredSlotId, SlotId, decrypt_data},
};
use zeroize::Zeroize;

const MAGIC: &[u8; 6] = b"OO7YK1";
const MASTER_KEY_LEN: usize = 32;
const POINT_LEN: usize = 33; // compressed SEC-1 P-256 point
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const INFO: &[u8] = b"oo7-yubikey-v1";
const SLOT: RetiredSlotId = RetiredSlotId::R1;

// File layout:
//   magic[6] | slot[1] | serial[4] | card_pub[33] | epk[33] | nonce[12] | ct+tag[48]
const FILE_LEN: usize = 6 + 1 + 4 + POINT_LEN + POINT_LEN + NONCE_LEN + MASTER_KEY_LEN + TAG_LEN;
const OFF_SLOT: usize = 6;
const OFF_SERIAL: usize = 7;
const OFF_CARD_PUB: usize = 11;
const OFF_EPK: usize = OFF_CARD_PUB + POINT_LEN;
const OFF_NONCE: usize = OFF_EPK + POINT_LEN;
const OFF_CT: usize = OFF_NONCE + NONCE_LEN;

#[derive(Clone, Debug)]
struct WrappedKey {
    slot: RetiredSlotId,
    serial: u32,
    card_pub: [u8; POINT_LEN],
    epk: [u8; POINT_LEN],
    nonce: [u8; NONCE_LEN],
    ct: [u8; MASTER_KEY_LEN + TAG_LEN],
}

fn wrapped_key_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("oo7").join("yubikey-master-key.bin")
}

impl WrappedKey {
    fn read(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let data = fs::read(path)?;
        if data.len() != FILE_LEN {
            return Err(std::io::Error::other(format!(
                "wrapped key file has wrong length {} (expected {FILE_LEN})",
                data.len()
            )));
        }
        if &data[..MAGIC.len()] != MAGIC {
            return Err(std::io::Error::other(
                "wrapped key file has unexpected magic bytes",
            ));
        }
        let slot = RetiredSlotId::try_from(data[OFF_SLOT])
            .map_err(|_| std::io::Error::other("invalid slot in wrapped key file"))?;
        let serial = u32::from_le_bytes(
            data[OFF_SERIAL..OFF_CARD_PUB]
                .try_into()
                .map_err(|_| std::io::Error::other("invalid serial in wrapped key file"))?,
        );

        let mut card_pub = [0u8; POINT_LEN];
        card_pub.copy_from_slice(&data[OFF_CARD_PUB..OFF_EPK]);
        let mut epk = [0u8; POINT_LEN];
        epk.copy_from_slice(&data[OFF_EPK..OFF_NONCE]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[OFF_NONCE..OFF_CT]);
        let mut ct = [0u8; MASTER_KEY_LEN + TAG_LEN];
        ct.copy_from_slice(&data[OFF_CT..]);

        Ok(Self {
            slot,
            serial,
            card_pub,
            epk,
            nonce,
            ct,
        })
    }

    fn write(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut data = Vec::with_capacity(FILE_LEN);
        data.extend_from_slice(MAGIC);
        data.push(self.slot.into());
        data.extend_from_slice(&self.serial.to_le_bytes());
        data.extend_from_slice(&self.card_pub);
        data.extend_from_slice(&self.epk);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.ct);

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        // Write to a temporary file in the same directory and atomically rename
        // it into place, so a crash mid-write never leaves a truncated key file.
        // The file is created 0600 so only the user can read the wrapped key.
        let tmp = tmp_path_for(path);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&tmp)?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(&data)?;
            file.sync_all()
        })();
        drop(file);
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        fs::rename(&tmp, path)
    }
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(tmp)
}

fn kdf(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; 32], std::io::Error> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(INFO, &mut okm)
        .map_err(|e| std::io::Error::other(format!("hkdf expand failed: {e}")))?;
    Ok(okm)
}

/// Open the first available YubiKey.
fn open_yubikey() -> Result<YubiKey, std::io::Error> {
    let mut ctx = Context::open().map_err(|e| std::io::Error::other(format!("pcsc: {e}")))?;
    let mut iter = ctx
        .iter()
        .map_err(|e| std::io::Error::other(format!("pcsc: {e}")))?;
    let reader = iter
        .next()
        .ok_or_else(|| std::io::Error::other("no YubiKey found (is it plugged in?)"))?;
    reader.open().map_err(|e| {
        std::io::Error::other(format!(
            "failed to open YubiKey: {e} (another agent such as scdaemon or \
             yubikey-agent may be holding an exclusive connection)"
        ))
    })
}

/// Verify that the inserted YubiKey is the one that wrapped the key.
///
/// Checked before any touch-gated operation so a wrong key fails fast with a
/// clear message instead of waiting for a touch that can never succeed.
fn check_serial(wrapped: u32, actual: u32) -> Result<(), std::io::Error> {
    if wrapped != actual {
        return Err(std::io::Error::other(format!(
            "YubiKey serial mismatch: wrapped key expects serial {wrapped}, \
             inserted key is serial {actual}"
        )));
    }
    Ok(())
}

/// Best-effort desktop notification that the YubiKey is waiting for a touch.
///
/// `yubikey-touch-detector` cannot see PIV touches, so the daemon notifies on
/// its own via the session bus. Errors are ignored (a missing notification
/// daemon must never prevent unlocking).
async fn notify_waiting_for_touch() {
    let Ok(conn) = zbus::Connection::session().await else {
        return;
    };
    let _ = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "oo7",
                0u32,
                "",
                "YubiKey",
                "Touch your YubiKey to unlock the keyring",
                Vec::<String>::new(),
                std::collections::HashMap::<String, zbus::zvariant::Value>::new(),
                -1i32,
            ),
        )
        .await;
}

/// Wrap a fresh random master key with the P-256 key held in the retired PIV
/// slot, and write the wrapped key to disk.
///
/// The PIV key must already exist in the slot (generated with `ykman`, which
/// handles the management key). We read its public key from the slot's
/// self-signed certificate, so the management key is never needed here.
pub fn setup() -> Result<(), std::io::Error> {
    let mut yk = open_yubikey()?;

    let cert = Certificate::read(&mut yk, SlotId::Retired(SLOT)).map_err(|e| {
        std::io::Error::other(format!(
            "no key/certificate in slot 82 (RETIRED1): {e}\n\
             generate one first with:\n  \
             ykman piv keys generate 82 -a ECCP256 --touch-policy=always --pin-policy=never\n  \
             ykman piv certificates generate 82 -s \"oo7\""
        ))
    })?;

    let card_point = match cert.subject_pki() {
        PublicKeyInfo::EcP256(point) => point,
        _ => return Err(std::io::Error::other("key in slot 82 is not P-256")),
    };

    let card_pub = PublicKey::from_sec1_bytes(card_point.as_bytes())
        .map_err(|e| std::io::Error::other(format!("invalid public key in cert: {e}")))?;
    let card_pub_compressed = card_pub.to_encoded_point(true);

    // Fresh random master key.
    let mut master_key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut master_key);

    // Wrap: ephemeral P-256 ECDH in software against the card's public key.
    let esk = EphemeralSecret::random(&mut OsRng);
    let epk = esk.public_key();
    let shared = esk.diffie_hellman(&card_pub);
    let epk_compressed = epk.to_encoded_point(true);

    let mut salt = Vec::with_capacity(POINT_LEN * 2);
    salt.extend_from_slice(epk_compressed.as_bytes());
    salt.extend_from_slice(card_pub_compressed.as_bytes());

    let mut kek = kdf(shared.raw_secret_bytes(), &salt)?;

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&kek)
        .map_err(|e| std::io::Error::other(format!("aes-gcm key: {e}")))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), master_key.as_slice())
        .map_err(|e| std::io::Error::other(format!("aes-gcm encrypt: {e}")))?;

    let wrapped = WrappedKey {
        slot: SLOT,
        serial: u32::from(yk.serial()),
        card_pub: card_pub_compressed
            .as_bytes()
            .try_into()
            .map_err(|_| std::io::Error::other("card public key is not 33 bytes"))?,
        epk: epk_compressed
            .as_bytes()
            .try_into()
            .map_err(|_| std::io::Error::other("ephemeral public key is not 33 bytes"))?,
        nonce,
        ct: ct
            .try_into()
            .map_err(|_| std::io::Error::other("ciphertext is not 48 bytes"))?,
    };
    let path = wrapped_key_path();
    wrapped.write(&path)?;

    master_key.zeroize();
    kek.zeroize();

    println!("Wrapped master key written to {}", path.display());
    Ok(())
}

/// Recover the master key via on-card ECDH (touch-gated) and decrypt the
/// wrapped key.
pub async fn unlock() -> Result<Vec<u8>, std::io::Error> {
    let path = wrapped_key_path();
    let wrapped = WrappedKey::read(&path)?;

    let mut yk = open_yubikey()?;

    check_serial(wrapped.serial, u32::from(yk.serial()))?;

    // Rebuild the salt used at wrap time.
    let mut salt = Vec::with_capacity(POINT_LEN * 2);
    salt.extend_from_slice(&wrapped.epk);
    salt.extend_from_slice(&wrapped.card_pub);

    // The PIV key-agreement instruction expects the uncompressed SEC-1 point.
    let epk_pub = PublicKey::from_sec1_bytes(&wrapped.epk)
        .map_err(|e| std::io::Error::other(format!("invalid stored ephemeral point: {e}")))?;
    let epk_uncompressed = epk_pub.to_encoded_point(false);

    // On-card ECDH. This blocks until the user touches the YubiKey (touch
    // policy "always").
    tracing::info!("Waiting for YubiKey touch to unlock keyring...");
    notify_waiting_for_touch().await;
    let shared = decrypt_data(
        &mut yk,
        epk_uncompressed.as_bytes(),
        AlgorithmId::EccP256,
        SlotId::Retired(wrapped.slot),
    )
    .map_err(|e| std::io::Error::other(format!("yubikey ECDH failed: {e}")))?;

    let mut kek = kdf(shared.as_ref(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek)
        .map_err(|e| std::io::Error::other(format!("aes-gcm key: {e}")))?;
    let master_key = cipher
        .decrypt(Nonce::from_slice(&wrapped.nonce), wrapped.ct.as_ref())
        .map_err(|e| std::io::Error::other(format!("aes-gcm decrypt: {e} (wrong YubiKey key?)")))?;

    kek.zeroize();

    if master_key.len() != MASTER_KEY_LEN {
        return Err(std::io::Error::other(
            "decrypted master key has wrong length",
        ));
    }

    Ok(master_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample() -> WrappedKey {
        WrappedKey {
            slot: SLOT,
            serial: 0xDEAD_BEEF,
            card_pub: [0x11; POINT_LEN],
            epk: [0x22; POINT_LEN],
            nonce: [0x33; NONCE_LEN],
            ct: [0x44; MASTER_KEY_LEN + TAG_LEN],
        }
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrapped.bin");
        let wk = sample();
        wk.write(&path).unwrap();
        let read = WrappedKey::read(&path).unwrap();
        assert_eq!(read.slot, wk.slot);
        assert_eq!(read.serial, wk.serial);
        assert_eq!(read.card_pub, wk.card_pub);
        assert_eq!(read.epk, wk.epk);
        assert_eq!(read.nonce, wk.nonce);
        assert_eq!(read.ct, wk.ct);
    }

    #[test]
    fn invalid_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.bin");
        std::fs::write(&path, [0u8; 10]).unwrap();
        let err = WrappedKey::read(&path).unwrap_err();
        assert!(
            err.to_string().contains("wrong length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("badmagic.bin");
        std::fs::write(&path, vec![0u8; FILE_LEN]).unwrap();
        let err = WrappedKey::read(&path).unwrap_err();
        assert!(err.to_string().contains("magic"), "unexpected error: {err}");
    }

    #[test]
    fn file_is_written_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("perm.bin");
        sample().write(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn serial_mismatch_is_rejected() {
        assert!(check_serial(1, 1).is_ok());
        let err = check_serial(1, 2).unwrap_err();
        assert!(
            err.to_string().contains("serial mismatch"),
            "unexpected error: {err}"
        );
    }
}
