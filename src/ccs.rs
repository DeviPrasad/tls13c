use crate::def::RecordContentType;
use crate::deser::DeSer;
use crate::err::Mutter;
use crate::protocol::Tls13Record;

#[derive(Debug)]
pub struct ChangeCipherSpecMsg {}

impl ChangeCipherSpecMsg {
    // look for the byte sequence of length 6: <20 03 03 00 01 01>
    pub fn deserialize(deser: &mut DeSer) -> Result<Option<(Self, usize)>, Mutter> {
        let rec = Tls13Record::peek(deser)?;
        if rec.rct == RecordContentType::ChangeCipherSpec {
            if rec.len == 1 && deser.peek_u8_at(5) == 1 {
                //deser.seek(deser.cursor() + 6);
                Ok(Some((ChangeCipherSpecMsg {}, 6)))
            } else {
                Mutter::ExpectingChangeCipherSpec.into()
            }
        } else {
            return Ok(None);
        }
    }

    pub fn bytes<'a>() -> &'a [u8] {
        [0x20, 0x03, 0x03, 0x00, 0x01, 0x01].as_slice()
    }
}
