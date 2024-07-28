use aead::{AeadInPlace, Key, KeyInit, KeySizeUser};
use aead::consts::{U12, U16, U32};
use aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use aes_gcm::aes::cipher::crypto_common::OutputSizeUser;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crate::def::CipherSuite;
use crate::err::Mutter;

macro_rules! tls13c_crypto_cipher_inplace_decrypt {
    () => {
        fn decrypt_next(&mut self, ad: &[u8], text: &mut Vec<u8>) -> Result<(), Mutter> {
            let mut nonce_bytes: [u8; 12] = [0; 12];
            assert_eq!(self.nonce.len(), 12);
            nonce_bytes.copy_from_slice(&self.nonce);
            nonce_bytes[11] ^= self.decrypted_rec_count;
            log::info!("decryption record  count {}", self.decrypted_rec_count);
            log::info!("decryption nonce {:?}", &nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            self.decrypted_rec_count += 1;
            self.cipher
                .decrypt_in_place(nonce, ad, text as &mut dyn aead::Buffer)
                .map_err(|_| Mutter::DecryptionFailed)
        }
    }
}

#[allow(dead_code)]
pub trait TlsCipher {
    fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter>;
    fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter>;
}

impl TryFrom<(Vec<u8>, Vec<u8>)> for TlsAes128GcmSha256Cipher {
    type Error = Mutter;

    fn try_from((key, nonce): (Vec<u8>, Vec<u8>)) -> Result<TlsAes128GcmSha256Cipher, Mutter> {
        if nonce.len() != 12 {
            Err(Mutter::AEADNonceLenBad)
        } else if key.len() != Aes128Gcm::key_size() {
            Err(Mutter::AEADKeyLenBad)
        } else if nonce.eq(&[0; 12]) {
            Err(Mutter::BadNonce)
        } else {
            let key = Key::<Aes128Gcm>::from_slice(&key);
            Ok(Self {
                nonce: *Nonce::from_slice(&nonce),
                key: *key,
                cipher: Aes128Gcm::new(key),
                decrypted_rec_count: 0,
                encrypted_rec_count: 0,
            })
        }
    }
}

impl TryFrom<(Vec<u8>, Vec<u8>)> for TlsAes256GcmSha384Cipher {
    type Error = Mutter;

    fn try_from((key, nonce): (Vec<u8>, Vec<u8>)) -> Result<TlsAes256GcmSha384Cipher, Mutter> {
        if nonce.len() != 12 {
            Err(Mutter::AEADNonceLenBad)
        } else if key.len() != Aes256Gcm::key_size() {
            Err(Mutter::AEADKeyLenBad)
        } else if nonce.eq(&[0; 12]) {
            Err(Mutter::BadNonce)
        } else {
            let key = Key::<Aes256Gcm>::from_slice(&key);
            Ok(Self {
                nonce: *Nonce::from_slice(&nonce),
                key: *key,
                cipher: Aes256Gcm::new(key),
                decrypted_rec_count: 0,
                encrypted_rec_count: 0,
            })
        }
    }
}

impl TryFrom<(Vec<u8>, Vec<u8>)> for TlsChaCha20Ploy1305Cipher {
    type Error = Mutter;

    fn try_from((key, nonce): (Vec<u8>, Vec<u8>)) -> Result<TlsChaCha20Ploy1305Cipher, Mutter> {
        if nonce.len() != 12 {
            Err(Mutter::AEADNonceLenBad)
        } else if key.len() != ChaCha20Poly1305::key_size() {
            Err(Mutter::AEADKeyLenBad)
        } else if nonce.eq(&[0; 12]) {
            Err(Mutter::BadNonce)
        } else {
            let key = Key::<ChaCha20Poly1305>::from_slice(&key);
            Ok(Self {
                nonce: *Nonce::from_slice(&nonce),
                key: *key,
                cipher: ChaCha20Poly1305::new(key),
                decrypted_rec_count: 0,
                encrypted_rec_count: 0,
            })
        }
    }
}

#[allow(dead_code)]
pub struct TlsAes128GcmSha256Cipher {
    nonce: GenericArray<u8, U12>,
    key: GenericArray<u8, U16>,
    cipher: Aes128Gcm,
    decrypted_rec_count: u8,
    encrypted_rec_count: u8,
}

impl TlsCipher for TlsAes128GcmSha256Cipher {
    tls13c_crypto_cipher_inplace_decrypt!();

    fn encrypt_next<'a>(&mut self, ad: &[u8], out: &'a mut Vec<u8>) -> Result<(), Mutter> {
        let mut nonce_bytes: [u8; 12] = [0; 12];
        assert_eq!(self.nonce.len(), 12);
        nonce_bytes.copy_from_slice(&self.nonce);
        nonce_bytes[11] ^= self.encrypted_rec_count;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.encrypted_rec_count += 1;
        self.cipher
            .encrypt_in_place(nonce, ad, out as &mut dyn aead::Buffer)
            .map(|_| ())
            .map_err(|_| Mutter::DecryptionFailed)
    }
}

#[allow(dead_code)]
pub struct TlsAes256GcmSha384Cipher {
    nonce: GenericArray<u8, U12>,
    key: GenericArray<u8, U32>,
    cipher: Aes256Gcm,
    decrypted_rec_count: u8,
    encrypted_rec_count: u8,
}
impl TlsCipher for TlsAes256GcmSha384Cipher {
    tls13c_crypto_cipher_inplace_decrypt!();

    fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        let mut nonce_bytes: [u8; 12] = [0; 12];
        assert_eq!(self.nonce.len(), 12);
        nonce_bytes.copy_from_slice(&self.nonce);
        nonce_bytes[11] ^= self.encrypted_rec_count;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.encrypted_rec_count += 1;
        self.cipher
            .encrypt_in_place(nonce, ad, out as &mut dyn aead::Buffer)
            // .map(|_| out as &Vec<u8>)
            .map(|_| ())
            .map_err(|_| Mutter::DecryptionFailed)
    }
}

#[allow(dead_code)]
pub struct TlsChaCha20Ploy1305Cipher {
    nonce: GenericArray<u8, U12>,
    key: GenericArray<u8, U32>,
    cipher: ChaCha20Poly1305,
    decrypted_rec_count: u8,
    encrypted_rec_count: u8,
}
impl TlsCipher for TlsChaCha20Ploy1305Cipher {
    tls13c_crypto_cipher_inplace_decrypt!();

    fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        let mut nonce_bytes: [u8; 12] = [0; 12];
        assert_eq!(self.nonce.len(), 12);
        nonce_bytes.copy_from_slice(&self.nonce);
        nonce_bytes[11] ^= self.encrypted_rec_count;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.encrypted_rec_count += 1;
        self.cipher
            .encrypt_in_place(nonce, ad, out as &mut dyn aead::Buffer)
            // .map(|_| out as &Vec<u8>)
            .map(|_| ())
            .map_err(|_| Mutter::DecryptionFailed)
    }
}

#[allow(dead_code)]
pub trait TlsCipherSuite {
    // type Aead: AeadCore + AeadInPlace + KeyInit + KeySizeUser;
    fn digest_size(&self) -> usize;

    fn key_size(&self) -> usize;

    fn nonce_len(&self) -> usize {
        12
    }

    fn handshake_secret(&self) -> Vec<u8>;

    fn set_hs_secret(&mut self, secret: Vec<u8>) -> bool;

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8>;

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter>;

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8>;

    fn hkdf_label(&self, secret: &[u8], label: &str, ctx: &[u8], output_len: u16) -> (Vec<u8>, u16) {
        // log::info!("hkdf_expand_label - label:{label:}, ctx:{ctx:?}, secret:{secret:?}");
        assert_eq!(secret.len(), self.digest_size());
        assert!(!label.is_empty() && label.len() <= 255);
        let label_len = ("tls13 ".len() + label.len()) as u16;
        assert!(label_len > 6 && label_len <= 255);
        let ctx_len = ctx.len() as u16;
        assert!(ctx.len() <= 255);
        let hkdf_label_full_len = 4 + label_len + ctx_len;
        assert!(hkdf_label_full_len <= 514);

        let mut hkdf_label: Vec<u8> = Vec::new(); //vec![0; hkdf_label_full_len as usize];
        let hash_len_bytes = output_len.to_be_bytes();
        hkdf_label.push(hash_len_bytes[0]); // 0
        hkdf_label.push(hash_len_bytes[1]); // 1
        // log::info!("hkdf_expand_label - label_len:{label_len:},\n\tctx_len:{ctx_len:},\n\thkdf_label_full_len:{hkdf_label_full_len:}\n\thash_len_bytes:{hash_len_bytes:?}");

        hkdf_label.push(label_len as u8); // 2
        hkdf_label.append(&mut ["tls13 ".as_bytes(), label.as_bytes()].concat()); // 3..3+label_len

        hkdf_label.push(ctx_len as u8); // 3+label_len
        if ctx_len > 0 {
            hkdf_label.resize(hkdf_label_full_len as usize, 0);
            hkdf_label[4 + label_len as usize..hkdf_label_full_len as usize].copy_from_slice(ctx)
        }
        (hkdf_label, hkdf_label_full_len)
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &str, ctx: &[u8], output_len: u16) -> Vec<u8>;

    fn derive_secret(&self, secret: &[u8], label: &str, messages: &[u8]) -> Vec<u8>;

    // Section 7.3. Traffic Key Calculation. page 95
    // 'key_len' is the length of the key being generated.
    // the purpose value "key" indicates the specific value being generated
    // The value of 'secret' for Handshake record type for server and client is
    // 'server_handshake_traffic_secret', and 'client_handshake_traffic_secret', respectively.
    // The value of 'secret' for Application Data record type is
    // 'server_application_traffic_secret' and 'client_application_traffic_secret', respectively.
    fn derive_server_handshake_authn_secrets(&mut self, dh: &[u8], hello_msg_ctx: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let early_secret = self.hkdf_extract(
            [0].repeat(self.digest_size()).as_slice(),
            [0].repeat(self.digest_size()).as_slice());
        let salt_hs_traffic = self.derive_secret(&early_secret, "derived", &[]);
        let hs_secret = self.hkdf_extract(&salt_hs_traffic, dh);
        let server_hs_secret = self.derive_secret(&hs_secret, "s hs traffic", hello_msg_ctx);
        self.set_hs_secret(server_hs_secret.clone());
        let server_hs_key = self.hkdf_expand_label(&server_hs_secret, "key", &[], self.key_size() as u16);
        let server_hs_iv = self.hkdf_expand_label(&server_hs_secret, "iv", &[], self.nonce_len() as u16);
        (server_hs_secret, server_hs_key, server_hs_iv)
    }

    fn derive_server_app_traffic_secrets(&mut self, serv_hs_secret: Vec<u8>, hello_to_serv_fin_msg_ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let salt_app_data_traffic = self.derive_secret(&serv_hs_secret, "derived", &[]);
        let master_secret = self.hkdf_extract(&salt_app_data_traffic, [0].repeat(self.digest_size()).as_slice());
        let server_app_traffic_secret = self.derive_secret(&master_secret, "s ap traffic", hello_to_serv_fin_msg_ctx);
        self.set_hs_secret(server_app_traffic_secret.clone());
        let server_app_traffic_key = self.hkdf_expand_label(&server_app_traffic_secret, "key", &[], self.key_size() as u16);
        let server_app_traffic_iv = self.hkdf_expand_label(&server_app_traffic_secret, "iv", &[], self.nonce_len() as u16);
        (server_app_traffic_key, server_app_traffic_iv)
    }

    fn derive_client_app_traffic_secrets(&mut self, cl_hs_secret: Vec<u8>, hello_to_serv_fin_msg_ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let salt_app_data_traffic = self.derive_secret(&cl_hs_secret, "derived", &[]);
        let master_secret = self.hkdf_extract(&salt_app_data_traffic, [0].repeat(self.digest_size()).as_slice());
        let cl_app_traffic_secret = self.derive_secret(&master_secret, "c ap traffic", hello_to_serv_fin_msg_ctx);
        self.set_hs_secret(cl_app_traffic_secret.clone());
        let cl_app_traffic_key = self.hkdf_expand_label(&cl_app_traffic_secret, "key", &[], self.key_size() as u16);
        let cl_app_traffic_iv = self.hkdf_expand_label(&cl_app_traffic_secret, "iv", &[], self.nonce_len() as u16);
        (cl_app_traffic_key, cl_app_traffic_iv)
    }

    fn derive_client_handshake_authn_secrets(&mut self, dh: &[u8], hello_msg_ctx: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let early_secret = self.hkdf_extract(
            [0].repeat(self.digest_size()).as_slice(),
            [0].repeat(self.digest_size()).as_slice());
        let salt_hs_traffic = self.derive_secret(&early_secret, "derived", &[]);
        let hs_secret = self.hkdf_extract(&salt_hs_traffic, dh);
        let cl_hs_secret = self.derive_secret(&hs_secret, "c hs traffic", hello_msg_ctx);
        self.set_hs_secret(cl_hs_secret.clone());
        let cl_hs_key = self.hkdf_expand_label(&cl_hs_secret, "key", &[], self.key_size() as u16);
        let cl_iv = self.hkdf_expand_label(&cl_hs_secret, "iv", &[], self.nonce_len() as u16);
        (cl_hs_secret, cl_hs_key, cl_iv)
    }

    fn derive_finished_key(&self, base_key: &[u8]) -> Vec<u8> {
        self.hkdf_expand_label(base_key, "finished", &[], self.digest_size() as u16)
    }

    // 'base_key' is 'client_hs_secret' (client_handshake_traffic_secret in sec 7.1, page 93)
    fn derive_client_finished_verify_data(&self, base_key: &[u8], hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        let finished_key = self.derive_finished_key(base_key);
        self.hmac(&finished_key, &self.transcript_hash(hs_ctx))
    }

    // 'base_key' is 'server_hs_secret' (server_handshake_traffic_secret in sec 7.1, page 93)
    fn derive_server_finished_verify_data(&self, base_key: &[u8], hs_ctx: &[u8]) -> Result<Vec<u8>, Mutter> {
        let finished_key = self.derive_finished_key(base_key);
        self.hmac(&finished_key, &self.transcript_hash(hs_ctx))
    }

    fn server_authn_cipher(&self, key: Vec<u8>, nonce: Vec<u8>, rec_count: u8) -> Box<dyn TlsCipher>;
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct TlsAes128GcmSha256CipherSuite {
    pub(crate) hs_secret: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct TlsAes256GcmSha384CipherSuite {
    pub(crate) hs_secret: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
// pub struct TlsChacha20Poly1305Sha256Cipher {
pub struct TlsChaCha20Poly1305Sha256CipherSuite {
    pub(crate) hs_secret: Vec<u8>,
}

#[allow(dead_code)]
impl TlsChaCha20Poly1305Sha256CipherSuite {}

#[allow(dead_code)]
impl TlsAes128GcmSha256CipherSuite {}

#[allow(dead_code)]
impl TlsAes256GcmSha384CipherSuite {}

#[allow(dead_code)]
impl TlsCipherSuite for TlsChaCha20Poly1305Sha256CipherSuite {
    fn digest_size(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }

    fn key_size(&self) -> usize {
        ChaCha20Poly1305::key_size()
    }

    fn handshake_secret(&self) -> Vec<u8> {
        assert!(self.hs_secret.len() > 0);
        self.hs_secret.clone()
    }

    fn set_hs_secret(&mut self, secret: Vec<u8>) -> bool {
        //assert_eq!(self.hs_secret.len(), 0);
        self.hs_secret = secret.clone();
        secret.len() > 0
    }

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8> {
        transcript_hash::<Sha256>(ctx)
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
        hmac_sha256(key, data)
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        assert_eq!(prk.len(), self.digest_size());
        assert_ne!(prk.as_slice(), [0].repeat(self.digest_size()));
        prk.to_vec()
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &str, ctx: &[u8], output_len: u16) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("TlsChacha20Poly1305Sha256 - random secret value to be large enough");
        let (hkdf_label, hkdf_label_full_len) = self.hkdf_label(secret, label, ctx, output_len);
        let mut okm = vec![0u8; output_len as usize];
        hk.expand(&hkdf_label, &mut okm).expect("TlsChacha20Poly1305Sha256 - sufficient Sha256 output length to expand");
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

    fn server_authn_cipher(&self, key: Vec<u8>, nonce: Vec<u8>, rec_count: u8) -> Box<dyn TlsCipher> {
        let mut cipher = TlsChaCha20Ploy1305Cipher::try_from((key, nonce)).unwrap();
        cipher.decrypted_rec_count = rec_count;
        cipher.encrypted_rec_count = 0;
        Box::new(cipher)
    }
}

#[allow(dead_code)]
impl TlsCipherSuite for TlsAes128GcmSha256CipherSuite {
    fn digest_size(&self) -> usize {
        <Sha256 as OutputSizeUser>::output_size()
    }

    fn key_size(&self) -> usize {
        Aes128Gcm::key_size()
    }

    fn handshake_secret(&self) -> Vec<u8> {
        assert!(self.hs_secret.len() > 0);
        self.hs_secret.clone()
    }

    fn set_hs_secret(&mut self, secret: Vec<u8>) -> bool {
        // assert_eq!(self.hs_secret.len(), 0);
        self.hs_secret = secret.clone();
        secret.len() > 0
    }

    fn transcript_hash(&self, ctx: &[u8]) -> Vec<u8> {
        transcript_hash::<Sha256>(ctx)
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
        hmac_sha256(key, data)
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        assert_eq!(prk.len(), self.digest_size());
        assert_ne!(prk.as_slice(), [0].repeat(self.digest_size()));
        prk.to_vec()
    }

    fn hkdf_expand_label(&self, secret: &[u8], label: &str, ctx: &[u8], output_len: u16) -> Vec<u8> {
        let (hkdf_label, hkdf_label_full_len) = self.hkdf_label(secret, label, ctx, output_len);
        let mut okm = vec![0u8; output_len as usize];
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("TlsAes128GcmSha256 - random secret value should be large enough");
        hk.expand(&hkdf_label, &mut okm).expect("TlsAes128GcmSha256 - sufficient Sha256 output length to expand");
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

    fn server_authn_cipher(&self, key: Vec<u8>, nonce: Vec<u8>, rec_count: u8) -> Box<dyn TlsCipher> {
        let mut cipher = TlsAes128GcmSha256Cipher::try_from((key, nonce)).unwrap();
        cipher.decrypted_rec_count = rec_count;
        Box::new(cipher)
    }
}

#[allow(dead_code)]
impl TlsCipherSuite for TlsAes256GcmSha384CipherSuite {
    fn digest_size(&self) -> usize {
        <Sha384 as OutputSizeUser>::output_size()
    }

    fn key_size(&self) -> usize {
        Aes256Gcm::key_size()
    }

    fn handshake_secret(&self) -> Vec<u8> {
        assert!(self.hs_secret.len() > 0);
        self.hs_secret.clone()
    }

    fn set_hs_secret(&mut self, secret: Vec<u8>) -> bool {
        // assert_eq!(self.hs_secret.len(), 0);
        self.hs_secret = secret.clone();
        secret.len() > 0
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

    fn hkdf_expand_label(&self, secret: &[u8], label: &str, ctx: &[u8], output_len: u16) -> Vec<u8> {
        let (hkdf_label, hkdf_label_full_len) = self.hkdf_label(secret, label, ctx, output_len);
        let mut okm = vec![0u8; output_len as usize];
        let hk = Hkdf::<Sha384>::from_prk(secret).expect("random secret value to be large enough");
        hk.expand(&hkdf_label, &mut okm).expect("sufficient Sha384 output length to expand");
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

    fn server_authn_cipher(&self, key: Vec<u8>, nonce: Vec<u8>, rec_count: u8) -> Box<dyn TlsCipher> {
        let mut cipher = TlsAes256GcmSha384Cipher::try_from((key, nonce)).unwrap();
        cipher.decrypted_rec_count = rec_count;
        Box::new(cipher)
    }
}

#[allow(dead_code)]
pub fn tls_cipher_suite_try_from(cipher_suite: CipherSuite) -> Result<Box<dyn TlsCipherSuite>, Mutter> {
    match cipher_suite {
        CipherSuite::TlsAes128GcmSha256 =>
            Ok(Box::new(TlsAes128GcmSha256CipherSuite::default())),
        CipherSuite::TlsChacha20Poly1305Sha256 =>
            Ok(Box::new(TlsChaCha20Poly1305Sha256CipherSuite::default())),
        CipherSuite::TlsAes256GcmSha384 =>
            Ok(Box::new(TlsAes256GcmSha384CipherSuite::default())),
        _ => Mutter::CipherSuiteLen.into()
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
    let mut hmac_sha256 = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
        .map_err(|_| Mutter::HmacBadKeyLen)?;
    hmac_sha256.update(&data);
    Ok(hmac_sha256.finalize().into_bytes().to_vec())
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Mutter> {
    let mut hmac_sha384 = <Hmac<Sha384> as KeyInit>::new_from_slice(&key)
        .map_err(|_| Mutter::HmacBadKeyLen)?;
    hmac_sha384.update(&data);
    Ok(hmac_sha384.finalize().into_bytes().to_vec())
}

fn transcript_hash<D: Digest>(ctx: &[u8]) -> Vec<u8> {
    let mut digest = D::new();
    digest.update(&ctx);
    digest.finalize().to_vec()
}

#[cfg(test)]
mod crypto_tests {
    use crate::cipher::{TlsAes128GcmSha256Cipher, TlsAes256GcmSha384Cipher, TlsAes256GcmSha384CipherSuite, TlsChaCha20Ploy1305Cipher, TlsCipher, TlsCipherSuite};

    #[test]
    fn tls_aes128gcm_sha256() {
        let res_aead = TlsAes128GcmSha256Cipher::try_from((vec![2; 16], vec![1; 12]));
        assert!(matches!(res_aead, Ok(_)));
        let aead: &mut dyn TlsCipher = &mut res_aead.unwrap();
        assert!(aead.decrypt_next(&[3].repeat(12), &mut Vec::from([0].repeat(32))).is_err());
    }

    #[test]
    fn tls_aes256gcm_sha384() {
        let _aes256_gcm_sha384: &dyn TlsCipherSuite = &TlsAes256GcmSha384CipherSuite::default();
        let res_aead = TlsAes256GcmSha384Cipher::try_from((vec![2; 32], vec![1; 12]));
        assert!(matches!(res_aead, Ok(_)));
        let aead = res_aead.unwrap();
        assert_eq!(aead.nonce.len(), 12);
    }

    #[test]
    fn tls_chacha20poly1305_sha256() {
        let res_aead = TlsChaCha20Ploy1305Cipher::try_from((vec![2; 32], vec![1; 12]));
        assert!(matches!(res_aead, Ok(_)));
        let aead = res_aead.unwrap();
        assert_eq!(aead.key.len(), 32);
    }
}
