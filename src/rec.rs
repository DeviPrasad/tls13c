use crate::def::LegacyTlsVersion::TlsLegacyVersion03003;
use crate::def::{self, LegacyRecordVersion, ProtoColVersion, RecordContentType};
use crate::deser::DeSer;
use crate::err::Mutter;
use crate::session::KeyExchangeSession;
use crate::stream::TlsStream;

#[derive(Debug)]
pub struct Tls13Record {
    pub(crate) rct: RecordContentType,
    pub(crate) ver: LegacyRecordVersion,
    pub(crate) len: u16,
}

pub trait RecordFetcher {
    fn fetch(deser: &DeSer) -> Result<(bool, usize), ()>;
}

pub fn try_fetch<S: RecordFetcher>(
    serv_stream: &mut TlsStream,
    tls_buf: &mut Vec<u8>,
    need: usize,
) -> bool {
    let mut require = need;
    let mut cache = vec![0; 0];
    while require > 0 {
        match serv_stream.fulfill(require, &mut cache) {
            Ok(_) => {
                let deser = DeSer::new(&cache);
                if let Ok((adequate, size)) = S::fetch(&deser) {
                    if adequate {
                        tls_buf.extend(cache);
                        return true;
                    } else {
                        require = size
                    }
                } else {
                    return false;
                }
            }
            Err(_e) => {
                // log::error!("try_fetch - Error {:#?}", e);
                return false;
            }
        }
    }
    false
}

#[allow(dead_code)]
impl Tls13Record {
    pub const SIZE: usize = 5;

    pub fn deserialize(deser: &mut DeSer) -> Result<Tls13Record, Mutter> {
        Self::peek(deser).map(|rec| (deser.seek(5), rec).1)
    }

    pub fn peek(deser: &DeSer) -> Result<Tls13Record, Mutter> {
        if deser.have(deser.cursor() + 5) {
            let ct = RecordContentType::try_from(deser.peek_u8())?;
            let ver = deser.peek_u16_at(1);
            let len = deser.peek_u16_at(3);
            if KeyExchangeSession::LEGACY_VER_0X0303 == ver && len > 0 {
                Ok(Tls13Record {
                    rct: ct,
                    ver: LegacyRecordVersion::default(),
                    len,
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
}

impl RecordFetcher for Tls13Record {
    fn fetch(deser: &DeSer) -> Result<(bool, usize), ()> {
        match Tls13Record::peek(deser) {
            Ok(rec) => {
                if deser.have(Tls13Record::SIZE + rec.len as usize) {
                    Ok((true, Tls13Record::SIZE + rec.len as usize))
                } else {
                    Ok((
                        false,
                        (Tls13Record::SIZE + rec.len as usize) - deser.available(),
                    ))
                }
            }
            Err(Mutter::DeserializationBufferInsufficient) => {
                Ok((false, Tls13Record::SIZE - deser.available()))
            }
            _ => Err(()),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tls13Ciphertext {
    opaque_type: RecordContentType, // u8
    ver: ProtoColVersion,           // u16
    len: u16,
}

#[allow(dead_code)]
impl Default for Tls13Ciphertext {
    fn default() -> Self {
        Self {
            opaque_type: RecordContentType::ApplicationData,
            ver: TlsLegacyVersion03003 as u16,
            len: 0,
        }
    }
}

impl Tls13Ciphertext {
    pub const SIZE: usize = 5;

    // additional authenticated data
    pub fn aad(size: u16) -> [u8; 5] {
        let mut ct_aad = [0u8; 5];
        ct_aad[0] = RecordContentType::ApplicationData as u8;
        (ct_aad[1], ct_aad[2]) = (0x03, 0x03);
        (ct_aad[3], ct_aad[4]) = def::u16_to_u8_pair(size);
        ct_aad
    }

    pub fn serialize(enc_rec: Vec<u8>) -> Vec<u8> {
        let mut ct = vec![0; 5 + enc_rec.len()];
        ct[0] = RecordContentType::ApplicationData as u8;
        (ct[1], ct[2]) = (0x03, 0x03);
        (ct[3], ct[4]) = def::u16_to_u8_pair(enc_rec.len() as u16);
        ct[5..].copy_from_slice(&enc_rec);
        ct
    }
}

impl RecordFetcher for Tls13Ciphertext {
    fn fetch(deser: &DeSer) -> Result<(bool, usize), ()> {
        if !deser.have(Self::SIZE) {
            return Ok((false, Self::SIZE - deser.available()));
        }
        if RecordContentType::ApplicationData as u8 != deser.peek_u8() {
            log::error!(
                "Error - expecting cipher text application data header - {}",
                deser.peek_u8()
            );
            return Err(());
        }
        if deser.peek_u16_at(1) != TlsLegacyVersion03003 as u16 {
            log::error!("Error - expecting cipher text legacy tls version (0x0303)");
            return Err(());
        }
        let len = deser.peek_u16_at(3) as usize;
        if deser.have(len) {
            Ok((true, len))
        } else {
            Ok((false, len - deser.available()))
        }
    }
}

pub struct Tls13InnerPlaintext {}

impl RecordFetcher for Tls13InnerPlaintext {
    fn fetch(deser: &DeSer) -> Result<(bool, usize), ()> {
        Ok((true, deser.len()))
    }
}
