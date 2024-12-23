use crate::def::RecordContentType;
use crate::deser::DeSer;
use crate::err::Error;
use crate::rec::Tls13Record;

#[derive(Debug)]
pub struct ChangeCipherSpecMsg {}

impl ChangeCipherSpecMsg {
    // look for the byte sequence of length 6: <20 03 03 00 01 01>
    pub fn deserialize(deser: &mut DeSer) -> Result<Option<(Self, usize)>, Error> {
        let rec = Tls13Record::peek(deser)?;
        if rec.rct == RecordContentType::ChangeCipherSpec {
            if rec.len == 1 && deser.peek_u8_at(5) == 1 {
                //deser.seek(deser.cursor() + 6);
                Ok(Some((ChangeCipherSpecMsg {}, 6)))
            } else {
                Error::ExpectingChangeCipherSpec.into()
            }
        } else {
            Ok(None)
        }
    }
}
