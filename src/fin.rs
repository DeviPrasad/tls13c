use crate::def::HandshakeType;
use crate::deser::DeSer;
use crate::err::Mutter;

pub struct FinishedMsg {
    head: [u8; 4],
    mac: Vec<u8>,
}

impl FinishedMsg {
    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, usize), Mutter> {
        if !deser.have(4) {
            return Mutter::DeserializationBufferInsufficient.into()
        }
        if deser.peek_u8() != HandshakeType::Finished as u8 {
            return Mutter::ExpectingFinishedMsg.into()
        };
        let len = deser.peek_u24_at(1) as usize;
        if !deser.have(4 + len) {
            return Mutter::DeserializationBufferInsufficient.into()
        }
        let head: [u8; 4] = deser.slice(4)
                                 .try_into()
                                 .map_err(|_| Mutter::InternalError)?;
        let mac = deser.slice(len);
        Ok((FinishedMsg {
            head,
            mac: mac.into(),
        }, 4 + len))
    }

    pub fn serialize() {}

    pub fn check_mac(&self, tag: Vec<u8>) -> Result<(), Mutter> {
        if self.mac == tag {
            Ok(())
        } else {
            Mutter::FinishMsgVerificationFailed.into()
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [self.head.as_slice(), self.mac.as_slice()].concat()
    }
}
