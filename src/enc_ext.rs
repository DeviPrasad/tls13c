use crate::def::{HandshakeType};
use crate::deser::DeSer;
use crate::err::Mutter;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EncryptedExtensionsMsg {
    extensions: Vec<u8>
}


#[allow(dead_code)]
impl EncryptedExtensionsMsg {
    pub fn new(ext: &[u8]) -> Self {
        Self {
            extensions: Vec::from(ext)
        }
    }

    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, usize), Mutter> {
        let msg_type: HandshakeType = deser.peek_u8().into();
        if msg_type == HandshakeType::EncryptedExtensions {
            deser.seek(deser.cursor() + 5);
            Mutter::NotImpl.into()
        } else {
            Mutter::ExpectingEncryptedExtensions.into()
        }
    }
}
