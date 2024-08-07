use std::marker::PhantomData;

#[allow(dead_code)]
pub trait TlsDH {
    fn public_key(&self) -> &[u8];
    fn dh(&self) -> &[u8];
}

#[allow(dead_code)]
pub trait TlsGroupX25519: TlsDH {}

#[allow(dead_code)]
pub trait TlsGroupSecp256r1: TlsDH {}

#[derive(Debug)]
pub struct GroupX25519 {
    phantom: PhantomData<u8>,
}

#[derive(Debug)]
pub struct GroupSecp256r1 {
    phantom: PhantomData<u8>,
}

#[allow(dead_code)]
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

impl TlsGroupX25519 for GroupX25519 {}
