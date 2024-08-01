use crate::def::HandshakeType;
use crate::deser::DeSer;
use crate::err::Mutter;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EncryptedExtensionsMsg {
}

#[allow(dead_code)]
impl EncryptedExtensionsMsg {
    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, Vec<u8>), Mutter> {
        if !deser.have(4) {
            return Mutter::DeserializationBufferInsufficient.into()
        }

        if HandshakeType::EncryptedExtensions != deser.peek_u8().into() {
            return Mutter::ExpectingEncryptedExtensions.into()
        }

        let len = deser.peek_u24_at(1) as usize;
        if !deser.have(4 + len) {
            return Mutter::DeserializationBufferInsufficient.into()
        }

        let head: [u8; 4] = deser.slice(4)
                                 .try_into()
                                 .map_err(|_| Mutter::InternalError)?;
        let extension_data = deser.slice(len);
        Ok((Self {}, [head.as_slice(), extension_data].concat()))
    }
}
