use crate::def;
use crate::def::{HandshakeType, RecordContentType};
use crate::deser::DeSer;
use crate::err::Mutter;

#[derive(Debug, Clone)]
pub struct FinishedMsg {
    mac: Vec<u8>,
}

impl FinishedMsg {
    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, Vec<u8>), Mutter> {
        if !deser.have(4) {
            return Mutter::DeserializationBufferInsufficient.into();
        }
        if deser.peek_u8() != HandshakeType::Finished as u8 {
            return Mutter::ExpectingFinishedMsg.into();
        };
        let len = deser.peek_u24_at(1) as usize;
        if !deser.have(4 + len) {
            return Mutter::DeserializationBufferInsufficient.into();
        }
        let head: [u8; 4] = deser
            .slice(4)
            .try_into()
            .map_err(|_| Mutter::InternalError)?;
        let mac = deser.slice(len);
        Ok((
            FinishedMsg {
                mac: mac.into(),
            },
            [&head, mac].concat(),
        ))
    }

    pub fn serialize(tag: Vec<u8>) -> Vec<u8> {
        let mut msg = vec![0u8; 4 + tag.len() + 1];
        msg[0] = HandshakeType::Finished as u8;
        // note msg[1] == 0
        (msg[1], msg[2], msg[3]) = def::u24_to_u8_triple(tag.len() as u32);
        msg[4..4 + tag.len()].copy_from_slice(&tag);
        msg[4 + tag.len()] = RecordContentType::Handshake as u8;
        msg
    }

    pub fn check_mac(&self, tag: Vec<u8>) -> Result<(), Mutter> {
        if self.mac == tag {
            Ok(())
        } else {
            Mutter::FinishMsgVerificationFailed.into()
        }
    }
}
