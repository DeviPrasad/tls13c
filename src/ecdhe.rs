use p256::elliptic_curve::sec1::EncodedPoint;
use p256::{
    ecdh::EphemeralSecret as P256EphemeralSecret, ecdh::SharedSecret as P256SharedSecret,
    EncodedPoint as P256EncodedPoint, NistP256, PublicKey as P256PublicKey,
};
use rand_core::OsRng;
use x25519_dalek::{
    EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey,
    SharedSecret as X25519SharedSecret,
};

use crate::err::Error;
use crate::ext::ServerPublicKey;

#[allow(dead_code)]
pub struct X25519KeyPair(X25519EphemeralSecret, X25519PublicKey);

#[allow(dead_code)]
impl Default for X25519KeyPair {
    fn default() -> Self {
        let sk = X25519EphemeralSecret::random();
        let pk = X25519PublicKey::from(&sk);
        Self(sk, pk)
    }
}

#[allow(dead_code)]
impl X25519KeyPair {
    pub fn public(&self) -> &X25519PublicKey {
        &self.1
    }

    fn private(self) -> X25519EphemeralSecret {
        self.0
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        self.public().as_bytes()
    }

    pub fn dh(self, peer_pk_bytes: [u8; 32]) -> X25519SharedSecret {
        let peer_pk = X25519PublicKey::from(peer_pk_bytes);
        self.private().diffie_hellman(&peer_pk)
    }
}

#[allow(dead_code)]
pub struct P256KeyPair(P256EphemeralSecret, P256PublicKey);

#[allow(dead_code)]
impl Default for P256KeyPair {
    fn default() -> Self {
        let sk = P256EphemeralSecret::random(&mut OsRng);
        let pk = sk.public_key();
        Self(sk, pk)
    }
}

#[allow(dead_code)]
impl P256KeyPair {
    pub fn public(&self) -> &P256PublicKey {
        &self.1
    }

    fn private(self) -> P256EphemeralSecret {
        self.0
    }

    pub fn public_bytes(&self) -> EncodedPoint<NistP256> {
        P256EncodedPoint::from(self.public())
    }

    pub fn dh(self, peer_pk_bytes: &[u8]) -> Result<P256SharedSecret, Error> {
        let peer_pk = P256PublicKey::from_sec1_bytes(peer_pk_bytes)
            .map_err(|_| Error::Secp256r1KeyLenBad)?;
        Ok(self.private().diffie_hellman(&peer_pk))
    }
}

#[allow(dead_code)]
pub trait TlsDH {
    fn public_key(&self) -> &[u8];
    fn dh(&self) -> &[u8];
}

#[derive(Debug)]
pub struct GroupX25519 {}

#[derive(Debug)]
pub struct GroupSecp256r1 {}

impl TlsDH for GroupX25519 {
    fn public_key(&self) -> &[u8] {
        &[]
    }

    fn dh(&self) -> &[u8] {
        &[]
    }
}

#[allow(dead_code)]
impl TlsDH for GroupSecp256r1 {
    fn public_key(&self) -> &[u8] {
        &[]
    }

    fn dh(&self) -> &[u8] {
        &[]
    }
}

pub struct DHSession {
    x25519_key_pair: X25519KeyPair,
    p256_key_pair: P256KeyPair,
}

#[allow(dead_code)]
impl DHSession {
    pub fn new() -> Self {
        Self {
            x25519_key_pair: X25519KeyPair::default(),
            p256_key_pair: P256KeyPair::default(),
        }
    }

    pub fn x25519_key_share(&mut self) -> ServerPublicKey {
        ServerPublicKey::x25519(self.x25519_key_pair.public_bytes())
    }

    pub fn p256_key_share(&mut self) -> ServerPublicKey {
        ServerPublicKey::secp256r1(self.p256_key_pair.public_bytes().as_bytes())
    }

    pub fn x25519_dh(self, pk: Vec<u8>) -> Vec<u8> {
        let dh_res = self.x25519_key_pair.dh(pk.try_into().unwrap());
        dh_res.to_bytes().as_slice().to_vec()
    }

    pub fn p256_dh(self, pk: Vec<u8>) -> Vec<u8> {
        let dh_res = self.p256_key_pair.dh(&pk).unwrap();
        dh_res.raw_secret_bytes().as_slice().to_vec()
    }
}
