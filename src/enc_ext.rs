use crate::def::HandshakeType;
use crate::deser::DeSer;
use crate::err::Error;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EncryptedExtensionsMsg {}

#[allow(dead_code)]
impl EncryptedExtensionsMsg {
    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, Vec<u8>), Error> {
        if !deser.have(4) {
            return Error::DeserializationBufferInsufficient.into();
        }

        if HandshakeType::EncryptedExtensions != deser.peek_u8().into() {
            return Error::ExpectingEncryptedExtensions.into();
        }

        let len = deser.peek_u24_at(1) as usize;
        if !deser.have(4 + len) {
            return Error::DeserializationBufferInsufficient.into();
        }

        let head: [u8; 4] = deser
            .slice(4)
            .try_into()
            .map_err(|_| Error::InternalError)?;
        let extension_data = deser.slice(len);
        Ok((Self {}, [head.as_slice(), extension_data].concat()))
    }
}
