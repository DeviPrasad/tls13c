use rand_core::{OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub struct CryptoRandom<const N: usize> ();

#[allow(dead_code)]
impl<const N: usize> CryptoRandom<N> {
    pub fn bytes() -> [u8; N] {
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}

#[allow(dead_code)]
pub struct X25519KeyPair(EphemeralSecret, PublicKey);

#[allow(dead_code)]
impl Default for X25519KeyPair {
    fn default() -> Self {
        let sk = EphemeralSecret::random();
        let pk = PublicKey::from(&sk);
        Self(sk, pk)
    }
}

#[allow(dead_code)]
impl X25519KeyPair {
    pub fn public(&self) -> &PublicKey {
        &self.1
    }

    fn private(self) -> EphemeralSecret {
        self.0
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        self.public().as_bytes()
    }

    pub fn dh(self, peer_pk_bytes: [u8; 32]) -> SharedSecret {
        let peer_pk = PublicKey::from(peer_pk_bytes);
        self.private().diffie_hellman(&peer_pk)
    }
}
