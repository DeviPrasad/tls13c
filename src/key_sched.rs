use crate::err::Mutter;

#[allow(dead_code)]
#[derive(Debug)]
pub struct KeySchedule {}

#[allow(dead_code)]
impl KeySchedule {
    pub fn derive_handshake_secrets() -> Result<Self, Mutter> {
        Mutter::NotImpl.into()
    }
}



