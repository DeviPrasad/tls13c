use rand_core::{OsRng, RngCore};

pub struct CryptoRandom<const N: usize>();

#[allow(dead_code)]
impl<const N: usize> CryptoRandom<N> {
    pub fn bytes() -> [u8; N] {
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}
