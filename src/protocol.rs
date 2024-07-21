use crate::def::{LegacyRecordVersion, RecordContentType};
use crate::err::Mutter;

#[allow(dead_code)]
pub(crate) struct DeSer<'a> {
    i: usize,
    bytes: &'a [u8],
}

#[allow(dead_code)]
impl<'a> DeSer<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            i: 0,
            bytes,
        }
    }

    pub fn pos(&self) -> usize {
        self.i
    }

    pub fn good_to_seek(&self, size: usize) -> bool {
        self.bytes.len() >= size
    }

    pub fn seek(&mut self, c: usize) {
        if c == 0 {
            log::warn!("seek zero!");
        }
        debug_assert!(self.i + c <= self.bytes.len(), "bad access");
        self.i += c;
    }

    pub fn peek_u8(&self) -> u8 {
        self.bytes[self.i]
    }

    pub fn peek_u8_at(&self, i: usize) -> u8 {
        self.bytes[i]
    }

    pub fn peek_u16_at(&self, i: usize) -> u16 {
        ((self.bytes[i] as u16) << 8) | (self.bytes[i + 1] as u16)
    }

    pub fn peek_u16(&self) -> u16 {
        ((self.bytes[self.i] as u16) << 8) | (self.bytes[self.i + 1] as u16)
    }

    pub fn peek_u24(&self) -> u32 {
        ((self.bytes[self.i] as u32) << 16) | ((self.bytes[self.i + 1] as u32) << 8) | (self.bytes[self.i + 2] as u32)
    }

    pub fn read_u8(&mut self) -> u8 {
        (self.peek_u8(), self.seek(1)).0
    }

    pub fn read_u16(&mut self) -> u16 {
        (self.peek_u16(), self.seek(2)).0
    }

    pub fn read_u24(&mut self) -> u32 {
        (self.peek_u24(), self.seek(3)).0
    }

    pub fn cmp_u8(&mut self, val: u8) -> bool {
        (self.bytes[self.i] == val, self.seek(1)).0
    }

    pub fn cmp_u16(&mut self, val: u16) -> bool {
        (self.peek_u16() == val, self.seek(2)).0
    }

    pub fn read_bytes(&mut self, n: usize) -> &'a [u8] {
        (&self.bytes[self.i..self.i + n], self.seek(n)).0
    }

    pub fn read_session_id(&mut self) -> Vec<u8> {
        let sid_len: usize = self.read_u8() as usize;
        if sid_len > 0 {
            Vec::from(self.read_bytes(sid_len))
        } else {
            Vec::new()
        }
    }

    pub fn read_empty_compression_methods(&mut self) -> Result<bool, Mutter> {
        if self.read_u8() == 0 {
            Ok(true)
        } else {
            Err(Mutter::CompressionMethods)
        }
    }

    pub fn read_tls13_record(&mut self) -> Result<Tls13Record, Mutter> {
        if self.i + 5 < self.bytes.len() {
            let ct = RecordContentType::try_from(self.peek_u8_at(self.i))?;
            let ver = self.peek_u16_at(self.i + 1);
            let len = self.peek_u16_at(self.i + 3);
            if Protocol::LEGACY_VER_0X0303 == ver && len > 0 {
                self.seek(5);
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

    pub fn read_tls13_handshake_record(&mut self) -> Result<Tls13Record, Mutter> {
        let rec = self.read_tls13_record()?;
        if rec.rct == RecordContentType::Handshake {
            Ok(rec)
        } else {
            Mutter::NotHandshakeMessage.into()
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tls13Record {
    pub(crate) rct: RecordContentType,
    pub(crate) ver: LegacyRecordVersion,
    pub(crate) len: u16,
}

pub struct Protocol {}

#[allow(dead_code)]
impl Protocol {
    pub const RECORD_HEADER_LEN: usize = 5;
    pub const LEGACY_VER_0X0303: u16 = 0x0303;
    pub const REC_SIZE_MAX: usize = 1 << 14;
    pub const MSG_SIZE_MAX: u32 = 1 << 14;
}