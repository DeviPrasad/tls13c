use crate::def::{LegacyRecordVersion, RecordContentType};
use crate::deser::DeSer;
use crate::err::Mutter;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tls13Record {
    pub(crate) rct: RecordContentType,
    pub(crate) ver: LegacyRecordVersion,
    pub(crate) len: u16,
}

#[derive(Debug)]
pub struct ChangeCipherSpecMsg(());
impl ChangeCipherSpecMsg {
    // look for the byte sequence of length 6: <20 03 03 00 01 01>
    pub fn deserialize(deser: &mut DeSer) -> Result<Option<(Self, usize)>, Mutter> {
        let rec = Tls13Record::peek(deser)?;
        if rec.rct == RecordContentType::ChangeCipherSpec &&
            rec.len == 1 &&
            deser.peek_u8_at(deser.cursor() + 5) == 1 {
            deser.seek(deser.cursor() + 6);
            Ok(Some((ChangeCipherSpecMsg(()), 6)))
        } else {
            return Ok(None)
        }
    }
}

#[allow(dead_code)]
impl Tls13Record {
    pub const SIZE: usize = 5;

    pub fn deserialize(deser: &mut DeSer) -> Result<Tls13Record, Mutter> {
        Self::peek(deser).map(|rec| (deser.seek(5), rec).1)
    }

    pub fn peek(deser: &mut DeSer) -> Result<Tls13Record, Mutter> {
        if deser.have(deser.cursor() + 5) {
            let ct = RecordContentType::try_from(deser.peek_u8())?;
            let ver = deser.peek_u16_at(deser.cursor() + 1);
            let len = deser.peek_u16_at(deser.cursor() + 3);
            log::info!("Tls13Record::deserialize {ct:#?} {ver} {len}");
            if Protocol::LEGACY_VER_0X0303 == ver && len > 0 {
                Ok(Tls13Record {
                    rct: ct,
                    ver: LegacyRecordVersion::default(),
                    len
                })
            } else {
                Mutter::NotTls13Record.into()
            }
        } else {
            Mutter::DeserializationBufferInsufficient.into()
        }
    }

    pub fn read_handshake(deser: &mut DeSer) -> Result<Tls13Record, Mutter> {
        let rec = Self::deserialize(deser)?;
        if rec.rct == RecordContentType::Handshake {
            Ok(rec)
        } else {
            Mutter::NotHandshakeMessage.into()
        }
    }

    pub fn read_cipher_spec_change(deser: &mut DeSer) -> Result<Tls13Record, Mutter> {
        let rec = Self::deserialize(deser)?;
        if rec.rct == RecordContentType::ChangeCipherSpec {
            Ok(rec)
        } else {
            Mutter::NotHandshakeMessage.into()
        }
    }
}

pub struct Protocol {}

#[allow(dead_code)]
impl Protocol {
    pub const RECORD_HEADER_LEN: usize = 5;
    pub const LEGACY_VER_0X0303: u16 = 0x0303;
    pub const REC_SIZE_MAX: usize = 1 << 14;
    pub const MSG_SIZE_MAX: u32 = 1 << 14;
}