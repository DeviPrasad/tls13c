use p256::elliptic_curve::sec1::EncodedPoint;
use p256::{
    ecdh::EphemeralSecret as P256EphemeralSecret, ecdh::SharedSecret as P256SharedSecret,
    EncodedPoint as P256EncodedPoint, NistP256, PublicKey as P256PublicKey,
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{
    EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey,
    SharedSecret as X25519SharedSecret,
};

use crate::err::Mutter;

pub struct CryptoRandom<const N: usize>();

#[allow(dead_code)]
impl<const N: usize> CryptoRandom<N> {
    pub fn bytes() -> [u8; N] {
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}

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

    pub fn dh(self, peer_pk_bytes: &[u8]) -> Result<P256SharedSecret, Mutter> {
        let peer_pk = P256PublicKey::from_sec1_bytes(peer_pk_bytes)
            .map_err(|_| Mutter::Secp256r1KeyLenBad)?;
        Ok(self.private().diffie_hellman(&peer_pk))
    }
}
