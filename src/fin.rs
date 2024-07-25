use crate::cipher::TlsCipher;
use crate::err::Mutter;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Finished {}

#[allow(dead_code)]
impl Finished {
    pub fn deserialize(_cipher: Box<dyn TlsCipher>, _buf: &mut [u8]) -> Result<(), Mutter> {
        Mutter::NotImpl.into()
    }
}