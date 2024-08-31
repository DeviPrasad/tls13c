use aead::consts::U12;
use aead::generic_array::GenericArray;
use aead::{AeadInPlace, Key, KeyInit, KeySizeUser};
use aes_gcm::aes::cipher::crypto_common::OutputSizeUser;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crate::def::CipherSuiteId;
use crate::err::Mutter;

macro_rules! tls13c_crypto_cipher_inplace_decrypt {
    () => {
        fn decrypt_next(&mut self, ad: &[u8], text: &mut Vec<u8>) -> Result<(), Mutter> {
            let mut iv_bytes: [u8; 12] = [0; 12];
            assert_eq!(self.iv.len(), 12);
            iv_bytes.copy_from_slice(&self.iv);
            if cfg!(target_endian = "little") {
                for (ivb, nrb) in iv_bytes.iter_mut().rev().zip(self.nr.to_ne_bytes().iter()) {
                    *ivb ^= *nrb;
                }
            } else {
                for (ivb, nrb) in iv_bytes.iter_mut().zip(self.nr.to_ne_bytes().iter()) {
                    *ivb ^= *nrb;
                }
            }
            let iv = Nonce::from_slice(&iv_bytes);
            self.nr += 1;
            self.cipher
                .decrypt_in_place(iv, ad, text as &mut dyn aead::Buffer)
                .map_err(|e| {
                    log::error!("decrypt_next error: {}", e);
                    Mutter::DecryptionFailed
                })
        }
    };
}

macro_rules! tls13c_crypto_cipher_inplace_encrypt {
    () => {
        fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
            let mut iv_bytes: [u8; 12] = [0; 12];
            assert_eq!(self.iv.len(), 12);
            iv_bytes.copy_from_slice(&self.iv);
            // rev() on little-endian arch
            if cfg!(target_endian = "little") {
                for (ivb, nrb) in iv_bytes.iter_mut().rev().zip(self.nr.to_ne_bytes().iter()) {
                    *ivb ^= *nrb;
                }
            } else {
                for (ivb, nrb) in iv_bytes.iter_mut().zip(self.nr.to_ne_bytes().iter()) {
                    *ivb ^= *nrb;
                }
            }
            let iv = Nonce::from_slice(&iv_bytes);
            self.nr += 1;
            self.cipher
                .encrypt_in_place(iv, ad, out as &mut dyn aead::Buffer)
                .map_err(|_| Mutter::DecryptionFailed)
        }
    };
}

macro_rules! derived_secrets {
    ($obj:expr,$master_secret: ident,$serv_secret:ident,$cl_secret:ident) => {
        (
            $master_secret,
            $obj.hkdf_expand_label(&$serv_secret, "key", &[], $obj.key_size() as u16),
            $obj.hkdf_expand_label(&$serv_secret, "iv", &[], $obj.nonce_len() as u16),
            $serv_secret,
            $obj.hkdf_expand_label(&$cl_secret, "key", &[], $obj.key_size() as u16),
            $obj.hkdf_expand_label(&$cl_secret, "iv", &[], $obj.nonce_len() as u16),
            $cl_secret,
        )
    };
}

pub type SymKey = Vec<u8>;
pub type IV = Vec<u8>;

#[allow(dead_code)]
pub trait TlsCipher {
    fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter>;
    fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter>;
}

impl TryFrom<(SymKey, IV)> for TlsAes128GcmSha256Cipher {
    type Error = Mutter;

    fn try_from((key, iv): (SymKey, IV)) -> Result<TlsAes128GcmSha256Cipher, Mutter> {
        if iv.len() != 12 {
            Err(Mutter::AEADNonceLenBad)
        } else if key.len() != Aes128Gcm::key_size() {
            Err(Mutter::AEADKeyLenBad)
        } else if iv.eq(&[0; 12]) {
            Err(Mutter::BadIV)
        } else {
            let key = Key::<Aes128Gcm>::from_slice(&key);
            Ok(Self {
                iv: *Nonce::from_slice(&iv),
                cipher: Aes128Gcm::new(key),
                nr: 0,
            })
        }
    }
}

impl TryFrom<(SymKey, IV)> for TlsAes256GcmSha384Cipher {
    type Error = Mutter;

    fn try_from((key, iv): (SymKey, IV)) -> Result<TlsAes256GcmSha384Cipher, Mutter> {
        if iv.len() != 12 {
            Err(Mutter::AEADNonceLenBad)
        } else if key.len() != Aes256Gcm::key_size() {
            Err(Mutter::AEADKeyLenBad)
        } else if iv.eq(&[0; 12]) {
            Err(Mutter::BadIV)
        } else {
            let key = Key::<Aes256Gcm>::from_slice(&key);
            Ok(Self {
                iv: *Nonce::from_slice(&iv),
                cipher: Aes256Gcm::new(key),
                nr: 0,
            })
        }
    }
}

impl TryFrom<(SymKey, IV)> for TlsChaCha20Ploy1305Cipher {
    type Error = Mutter;

    fn try_from((key, nonce): (SymKey, IV)) -> Result<TlsChaCha20Ploy1305Cipher, Mutter> {
        if nonce.len() != 12 {
            Err(Mutter::AEADNonceLenBad)
        } else if key.len() != ChaCha20Poly1305::key_size() {
            Err(Mutter::AEADKeyLenBad)
        } else if nonce.eq(&[0; 12]) {
            Err(Mutter::BadIV)
        } else {
            let key = Key::<ChaCha20Poly1305>::from_slice(&key);
            Ok(Self {
                iv: *Nonce::from_slice(&nonce),
                cipher: ChaCha20Poly1305::new(key),
                nr: 0,
            })
        }
    }
}

pub struct TlsAes128GcmSha256Cipher {
    iv: GenericArray<u8, U12>,
    cipher: Aes128Gcm,
    nr: u64,
}

impl TlsCipher for TlsAes128GcmSha256Cipher {
    tls13c_crypto_cipher_inplace_decrypt!();

    tls13c_crypto_cipher_inplace_encrypt!();
}

pub struct TlsAes256GcmSha384Cipher {
    iv: GenericArray<u8, U12>,
    cipher: Aes256Gcm,
    nr: u64,
}

impl TlsCipher for TlsAes256GcmSha384Cipher {
    tls13c_crypto_cipher_inplace_decrypt!();

    tls13c_crypto_cipher_inplace_encrypt!();
}

pub struct TlsChaCha20Ploy1305Cipher {
    iv: GenericArray<u8, U12>,
    cipher: ChaCha20Poly1305,
    nr: u64,
}

impl TlsCipher for TlsChaCha20Ploy1305Cipher {
    tls13c_crypto_cipher_inplace_decrypt!();

    tls13c_crypto_cipher_inplace_encrypt!();
}

type DerivedSecrets = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub trait TlsCipherSuite {
    // type Aead: AeadCore + AeadInPlace + KeyInit + KeySizeUser;
    fn digest_size(&self) -> usize;

    fn key_size(&self) -> usize;

    fn nonce_len(&self) -> usize {
        12
    }

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8>;

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter>;

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8>;

    fn hkdf_label(
        &self,
        secret: &[u8],
        label: &str,
        ctx: &[u8],
        output_len: u16,
    ) -> (Vec<u8>, u16) {
        assert_eq!(secret.len(), self.digest_size());
        assert!(!label.is_empty() && label.len() <= 255);
        let label_len = ("tls13 ".len() + label.len()) as u16;
        assert!(label_len > 6 && label_len <= 255);
        let ctx_len = ctx.len() as u16;
        assert!(ctx.len() <= 255);
        let hkdf_label_full_len = 4 + label_len + ctx_len;
        assert!(hkdf_label_full_len <= 514);

        let mut hkdf_label: Vec<u8> = Vec::new();
        let hash_len_bytes = output_len.to_be_bytes();
        hkdf_label.push(hash_len_bytes[0]); // 0
        hkdf_label.push(hash_len_bytes[1]); // 1

        hkdf_label.push(label_len as u8); // 2
        hkdf_label.append(&mut ["tls13 ".as_bytes(), label.as_bytes()].concat()); // 3..3+label_len

        hkdf_label.push(ctx_len as u8); // 3+label_len
        if ctx_len > 0 {
            hkdf_label.resize(hkdf_label_full_len as usize, 0);
            hkdf_label[4 + label_len as usize..hkdf_label_full_len as usize].copy_from_slice(ctx)
        }
        (hkdf_label, hkdf_label_full_len)
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &str, ctx: &[u8], output_len: u16)
        -> Vec<u8>;

    fn derive_secret(&self, secret: &[u8], label: &str, messages: &[u8]) -> Vec<u8>;

    // Section 7.3. Traffic Key Calculation. page 95
    // 'key_len' is the length of the key being generated.
    // the purpose value "key" indicates the specific value being generated
    // The value of 'secret' for Handshake record type for server and client is
    // 'server_handshake_traffic_secret', and 'client_handshake_traffic_secret', respectively.
    // The value of 'secret' for Application Data record type is
    // 'server_application_traffic_secret' and 'client_application_traffic_secret', respectively.
    fn handshake_traffic_secrets(&self, dh: &[u8], hello_msg_ctx: &[u8]) -> DerivedSecrets {
        let early_secret = self.hkdf_extract(
            [0].repeat(self.digest_size()).as_slice(),
            [0].repeat(self.digest_size()).as_slice(),
        );
        let salt = self.derive_secret(&early_secret, "derived", &[]);
        let hs_secret_master = self.hkdf_extract(&salt, dh);
        let serv_hs_secret = self.derive_secret(&hs_secret_master, "s hs traffic", hello_msg_ctx);
        let cl_hs_secret = self.derive_secret(&hs_secret_master, "c hs traffic", hello_msg_ctx);
        derived_secrets!(self, hs_secret_master, serv_hs_secret, cl_hs_secret)
    }

    fn derive_app_traffic_secrets(
        &self,
        hs_secret_master: Vec<u8>,
        hello_to_serv_fin_msg_ctx: &[u8],
    ) -> DerivedSecrets {
        let salt = self.derive_secret(&hs_secret_master, "derived", &[]);
        let master_secret = self.hkdf_extract(&salt, [0].repeat(self.digest_size()).as_slice());
        let serv_app_traffic_secret =
            self.derive_secret(&master_secret, "s ap traffic", hello_to_serv_fin_msg_ctx);
        let cl_app_traffic_secret =
            self.derive_secret(&master_secret, "c ap traffic", hello_to_serv_fin_msg_ctx);

        derived_secrets!(
            self,
            master_secret,
            serv_app_traffic_secret,
            cl_app_traffic_secret
        )
    }

    fn derive_finished_key(&self, base_key: &[u8]) -> Vec<u8> {
        self.hkdf_expand_label(base_key, "finished", &[], self.digest_size() as u16)
    }

    // 'base_key' is 'client_hs_secret' (client_handshake_traffic_secret in sec 7.1, page 93)
    fn derive_finished_mac(&self, base_key: &[u8], hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        let finished_key = self.derive_finished_key(base_key);
        self.hmac(&finished_key, &self.transcript_hash(hs_ctx))
    }

    fn derive_certificate_verify_hash(&self, hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        Ok(self.transcript_hash(hs_ctx))
    }

    fn cipher(&self, key: Vec<u8>, nonce: Vec<u8>) -> Box<dyn TlsCipher>;
}

#[derive(Default)]
pub struct TlsAes128GcmSha256CipherSuite {}

#[derive(Default)]
pub struct TlsAes256GcmSha384CipherSuite {}

#[derive(Default)]
// pub struct TlsChacha20Poly1305Sha256Cipher {
pub struct TlsChaCha20Poly1305Sha256CipherSuite {}

impl TlsChaCha20Poly1305Sha256CipherSuite {}

impl TlsAes128GcmSha256CipherSuite {}

impl TlsAes256GcmSha384CipherSuite {}

impl TlsCipherSuite for TlsChaCha20Poly1305Sha256CipherSuite {
    fn digest_size(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }

    fn key_size(&self) -> usize {
        ChaCha20Poly1305::key_size()
    }

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8> {
        transcript_hash::<Sha256>(ctx)
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
        hmac_sha256(key, data)
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hkdf_sha256_extract(salt, ikm)
    }

    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &str,
        ctx: &[u8],
        output_len: u16,
    ) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::from_prk(secret)
            .expect("TlsChacha20Poly1305Sha256 - random secret value to be large enough");
        let (hkdf_label, hkdf_label_full_len) = self.hkdf_label(secret, label, ctx, output_len);
        let mut okm = vec![0u8; output_len as usize];
        hk.expand(&hkdf_label, &mut okm)
            .expect("TlsChacha20Poly1305Sha256 - sufficient Sha256 output length to expand");
        assert_ne!(okm, [0u8; 42]);
        assert_eq!(hkdf_label.len(), hkdf_label_full_len as usize);
        okm
    }

    fn derive_secret(&self, secret: &[u8], label: &str, messages: &[u8]) -> Vec<u8> {
        let mut sha256 = Sha256::new();
        sha256.update(messages);
        let hash = sha256.finalize();
        self.hkdf_expand_label(secret, label, &hash, self.digest_size() as u16)
    }

    fn cipher(&self, key: Vec<u8>, nonce: Vec<u8>) -> Box<dyn TlsCipher> {
        Box::new(TlsChaCha20Ploy1305Cipher::try_from((key, nonce)).unwrap())
    }
}

impl TlsCipherSuite for TlsAes128GcmSha256CipherSuite {
    fn digest_size(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }

    fn key_size(&self) -> usize {
        Aes128Gcm::key_size()
    }

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8> {
        transcript_hash::<Sha256>(ctx)
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
        hmac_sha256(key, data)
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hkdf_sha256_extract(salt, ikm)
    }

    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &str,
        ctx: &[u8],
        output_len: u16,
    ) -> Vec<u8> {
        let (hkdf_label, hkdf_label_full_len) = self.hkdf_label(secret, label, ctx, output_len);
        let mut okm = vec![0u8; output_len as usize];
        let hk = Hkdf::<Sha256>::from_prk(secret)
            .expect("TlsAes128GcmSha256 - random secret value should be large enough");
        hk.expand(&hkdf_label, &mut okm)
            .expect("TlsAes128GcmSha256 - sufficient Sha256 output length to expand");
        assert_ne!(okm, [0u8].repeat(output_len as usize));
        assert_eq!(hkdf_label.len(), hkdf_label_full_len as usize);
        okm
    }

    fn derive_secret(&self, secret: &[u8], label: &str, messages: &[u8]) -> Vec<u8> {
        let mut sha256 = Sha256::new();
        sha256.update(messages);
        let hash = sha256.finalize();
        assert_eq!(self.digest_size(), 32);
        self.hkdf_expand_label(secret, label, &hash, self.digest_size() as u16)
    }

    fn cipher(&self, key: Vec<u8>, nonce: Vec<u8>) -> Box<dyn TlsCipher> {
        Box::new(TlsAes128GcmSha256Cipher::try_from((key, nonce)).unwrap())
    }
}

impl TlsCipherSuite for TlsAes256GcmSha384CipherSuite {
    fn digest_size(&self) -> usize {
        <Sha384 as OutputSizeUser>::output_size()
    }

    fn key_size(&self) -> usize {
        Aes256Gcm::key_size()
    }

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8> {
        transcript_hash::<Sha384>(ctx)
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
        hmac_sha384(key, data)
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _hk) = Hkdf::<Sha384>::extract(Some(salt), ikm);
        assert_eq!(prk.len(), self.digest_size());
        assert_ne!(prk.as_slice(), [0].repeat(self.digest_size()));
        prk.to_vec()
    }

    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &str,
        ctx: &[u8],
        output_len: u16,
    ) -> Vec<u8> {
        let (hkdf_label, hkdf_label_full_len) = self.hkdf_label(secret, label, ctx, output_len);
        let mut okm = vec![0u8; output_len as usize];
        let hk = Hkdf::<Sha384>::from_prk(secret).expect("random secret value to be large enough");
        hk.expand(&hkdf_label, &mut okm)
            .expect("sufficient Sha384 output length to expand");
        assert_ne!(okm, [0u8; 42]);
        assert_eq!(hkdf_label.len(), hkdf_label_full_len as usize);
        okm
    }

    fn derive_secret(&self, secret: &[u8], label: &str, messages: &[u8]) -> Vec<u8> {
        let mut sha384 = Sha384::new();
        Digest::update(&mut sha384, messages);
        let hash = sha384.finalize();
        self.hkdf_expand_label(secret, label, &hash, self.digest_size() as u16)
    }

    fn cipher(&self, key: Vec<u8>, nonce: Vec<u8>) -> Box<dyn TlsCipher> {
        Box::new(TlsAes256GcmSha384Cipher::try_from((key, nonce)).unwrap())
    }
}

impl TryFrom<CipherSuiteId> for Box<dyn TlsCipherSuite> {
    type Error = Mutter;

    fn try_from(cs: CipherSuiteId) -> Result<Self, Mutter> {
        match cs {
            CipherSuiteId::TlsAes128GcmSha256 => {
                Ok(Box::new(TlsAes128GcmSha256CipherSuite::default()))
            }
            CipherSuiteId::TlsChacha20Poly1305Sha256 => {
                Ok(Box::new(TlsChaCha20Poly1305Sha256CipherSuite::default()))
            }
            CipherSuiteId::TlsAes256GcmSha384 => {
                Ok(Box::new(TlsAes256GcmSha384CipherSuite::default()))
            }
            _ => Mutter::UnsupportedCipherSuite.into(),
        }
    }
}

pub struct HandshakeSecrets {
    pub(crate) tls_cipher_suite_name: CipherSuiteId,
    cipher_suite: Box<dyn TlsCipherSuite>,
    hs_secret_master: Vec<u8>,
    serv_cipher: Box<dyn TlsCipher>,
    serv_hs_traffic_secret: Vec<u8>,
    cl_cipher: Box<dyn TlsCipher>,
    cl_hs_traffic_secret: Vec<u8>,
}

impl HandshakeSecrets {
    pub fn new(
        tls_cipher_suite_name: CipherSuiteId,
        cipher_suite: Box<dyn TlsCipherSuite>,
        hs_secret_master: Vec<u8>,
        serv_cipher: Box<dyn TlsCipher>,
        serv_hs_traffic_secret: Vec<u8>,
        cl_cipher: Box<dyn TlsCipher>,
        cl_hs_traffic_secret: Vec<u8>,
    ) -> Self {
        Self {
            tls_cipher_suite_name,
            cipher_suite,
            hs_secret_master,
            serv_cipher,
            serv_hs_traffic_secret,
            cl_cipher,
            cl_hs_traffic_secret,
        }
    }

    pub fn hs_traffic_secret_master(&self) -> Vec<u8> {
        self.hs_secret_master.clone()
    }

    pub fn digest_size(&self) -> usize {
        self.cipher_suite.digest_size()
    }

    pub fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.serv_cipher.decrypt_next(ad, out)
    }

    pub fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.cl_cipher.encrypt_next(ad, out)
    }

    pub fn server_finished_mac(&self, hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        self.cipher_suite
            .derive_finished_mac(&self.serv_hs_traffic_secret, hs_ctx)
    }

    pub fn server_certificate_verify_hash(&self, hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        self.cipher_suite.derive_certificate_verify_hash(hs_ctx)
    }

    pub fn client_finished_mac(&self, hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        self.cipher_suite
            .derive_finished_mac(&self.cl_hs_traffic_secret, hs_ctx)
    }
}

#[allow(dead_code)]
pub struct AppTrafficSecrets {
    tls_cipher_suite_name: CipherSuiteId,
    cipher_suite: Box<dyn TlsCipherSuite>,
    app_traffic_secret_master: Vec<u8>,
    serv_cipher: Box<dyn TlsCipher>,
    serv_app_traffic_secret: Vec<u8>,
    cl_cipher: Box<dyn TlsCipher>,
    cl_app_traffic_secret: Vec<u8>,
}

impl AppTrafficSecrets {
    pub fn new(
        tls_cipher_suite_name: CipherSuiteId,
        cipher_suite: Box<dyn TlsCipherSuite>,
        traffic_secret_master: Vec<u8>,
        serv_cipher: Box<dyn TlsCipher>,
        serv_app_traffic_secret: Vec<u8>,
        cl_cipher: Box<dyn TlsCipher>,
        cl_app_traffic_secret: Vec<u8>,
    ) -> Self {
        Self {
            tls_cipher_suite_name,
            cipher_suite,
            app_traffic_secret_master: traffic_secret_master,
            serv_cipher,
            serv_app_traffic_secret,
            cl_cipher,
            cl_app_traffic_secret,
        }
    }

    pub fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.serv_cipher.decrypt_next(ad, out)
    }

    pub fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.cl_cipher.encrypt_next(ad, out)
    }
}

fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    assert_eq!(prk.len(), 32);
    assert_ne!(prk.as_slice(), [0].repeat(32));
    prk.to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
    let mut hmac_sha256 =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| Mutter::HmacBadKeyLen)?;
    hmac_sha256.update(data);
    Ok(hmac_sha256.finalize().into_bytes().to_vec())
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
    let mut hmac_sha384 =
        <Hmac<Sha384> as KeyInit>::new_from_slice(key).map_err(|_| Mutter::HmacBadKeyLen)?;
    hmac_sha384.update(data);
    Ok(hmac_sha384.finalize().into_bytes().to_vec())
}

fn transcript_hash<D: Digest>(ctx: &[u8]) -> Vec<u8> {
    let mut digest = D::new();
    digest.update(ctx);
    digest.finalize().to_vec()
}

#[cfg(test)]
mod cipher_tests {
    use crate::cipher::{
        TlsAes128GcmSha256Cipher, TlsAes256GcmSha384Cipher, TlsAes256GcmSha384CipherSuite,
        TlsChaCha20Ploy1305Cipher, TlsCipher, TlsCipherSuite,
    };

    #[test]
    fn endian_nonce() {
        let counter = 5u64;
        assert_eq!(counter.to_be_bytes(), [0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(counter.to_le_bytes(), [5, 0, 0, 0, 0, 0, 0, 0]);
        if cfg!(target_endian = "little") {
            assert_eq!(counter.to_ne_bytes(), [5, 0, 0, 0, 0, 0, 0, 0]);
        } else {
            assert_eq!(counter.to_ne_bytes(), [0, 0, 0, 0, 0, 0, 0, 5]);
        }
    }

    #[test]
    fn tls_aes128gcm_sha256() {
        let res_aead = TlsAes128GcmSha256Cipher::try_from((vec![2; 16], vec![1; 12]));
        assert!(res_aead.is_ok());
        let aead: &mut dyn TlsCipher = &mut res_aead.unwrap();
        assert!(aead
            .decrypt_next(&[3].repeat(12), &mut [0].repeat(32))
            .is_err());
    }

    #[test]
    fn tls_aes256gcm_sha384() {
        let _aes256_gcm_sha384: &dyn TlsCipherSuite = &TlsAes256GcmSha384CipherSuite::default();
        let res_aead = TlsAes256GcmSha384Cipher::try_from((vec![2; 32], vec![1; 12]));
        assert!(res_aead.is_ok());
        let aead = res_aead.unwrap();
        assert_eq!(aead.iv.len(), 12);
    }

    #[test]
    fn tls_chacha20poly1305_sha256() {
        let res_aead = TlsChaCha20Ploy1305Cipher::try_from((vec![2; 32], vec![1; 12]));
        assert!(res_aead.is_ok());
    }
}
