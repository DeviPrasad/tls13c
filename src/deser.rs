use crate::err::Error;

//#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DeSer<'a> {
    i: usize,
    bytes: &'a [u8],
}

#[allow(dead_code)]
impl<'a> DeSer<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { i: 0, bytes }
    }

    pub fn cursor(&self) -> usize {
        self.i
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn available(&self) -> usize {
        self.bytes.len() - self.cursor()
    }

    pub fn have(&self, size: usize) -> bool {
        self.cursor() + size <= self.len()
    }

    pub fn seek(&mut self, offset: usize) {
        assert!(self.have(offset));
        if offset == 0 {
            log::warn!("seek zero!");
        }
        self.i += offset;
    }

    pub fn peek_u8(&self) -> u8 {
        assert!(self.cursor() < self.len());
        self.bytes[self.cursor()]
    }

    pub fn peek_u16(&self) -> u16 {
        assert!(self.cursor() + 1 < self.len());
        ((self.bytes[self.cursor()] as u16) << 8) | (self.bytes[self.cursor() + 1] as u16)
    }

    pub fn peek_u24(&self) -> u32 {
        assert!(self.cursor() + 2 < self.len());
        ((self.bytes[self.cursor()] as u32) << 16)
            | ((self.bytes[self.cursor() + 1] as u32) << 8)
            | (self.bytes[self.cursor() + 2] as u32)
    }

    // peek a 8 bit value at (cursor + i)
    pub fn peek_u8_at(&self, i: usize) -> u8 {
        assert!(self.cursor() + i < self.len());
        self.bytes[self.cursor() + i]
    }

    // peek a 16 bit value at (cursor + i)
    pub fn peek_u16_at(&self, i: usize) -> u16 {
        assert!(self.cursor() + i + 1 < self.len());
        let j = self.cursor() + i;
        ((self.bytes[j] as u16) << 8) | (self.bytes[j + 1] as u16)
    }

    // peek a 24 bit value at (cursor + i)
    pub fn peek_u24_at(&self, i: usize) -> u32 {
        assert!(self.cursor() + i + 2 < self.len());
        let j = self.cursor() + i;
        ((self.bytes[j] as u32) << 16)
            | ((self.bytes[j + 1] as u32) << 8)
            | (self.bytes[j + 2] as u32)
    }

    pub fn ru8(&mut self) -> u8 {
        (self.peek_u8(), self.seek(1)).0
    }

    pub fn ru16(&mut self) -> u16 {
        (self.peek_u16(), self.seek(2)).0
    }

    pub fn ru24(&mut self) -> u32 {
        (self.peek_u24(), self.seek(3)).0
    }

    pub fn cmp_u8(&mut self, val: u8) -> bool {
        (self.peek_u8() == val, self.seek(1)).0
    }

    pub fn cmp_u16(&mut self, val: u16) -> bool {
        (self.peek_u16() == val, self.seek(2)).0
    }

    pub fn slice(&mut self, n: usize) -> &'a [u8] {
        assert!(self.have(n));
        (&self.bytes[self.cursor()..self.cursor() + n], self.seek(n)).0
    }

    pub fn vlu8_vec(&mut self) -> Vec<u8> {
        let sid_len: usize = self.ru8() as usize;
        if sid_len > 0 {
            Vec::from(self.slice(sid_len))
        } else {
            Vec::new()
        }
    }

    pub fn zlu8(&mut self) -> Result<bool, Error> {
        if self.ru8() == 0 {
            Ok(true)
        } else {
            Err(Error::BadVarLenVec)
        }
    }
}
