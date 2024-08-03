use crate::ccs::ChangeCipherSpecMsg;
use crate::ch::ClientHelloMsg;
use crate::cipher::{HandshakeSecrets, TlsCipherSuite};
use crate::crypto;
use crate::crypto::{P256KeyPair, X25519KeyPair};
use crate::def::{CipherSuite, LegacyRecordVersion, ProtoColVersion, RecordContentType, SupportedGroup};
use crate::def::LegacyTlsVersion::TlsLegacyVersion03003;
use crate::deser::DeSer;
use crate::err::Mutter;
use crate::ext::KeyShare;
use crate::sh::ServerHelloMsg;
use crate::sock::{Stream, TlsStream};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tls13Record {
    pub(crate) rct: RecordContentType,
    pub(crate) ver: LegacyRecordVersion,
    pub(crate) len: u16,
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
            if Tls13ProtocolSession::LEGACY_VER_0X0303 == ver && len > 0 {
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
}

impl BufferSniffer for Tls13Record {
    fn sniff(deser: &DeSer) -> Result<(bool, usize), ()> {
        return match Tls13Record::peek(&deser) {
            Ok(rec) => {
                if deser.have(Tls13Record::SIZE + rec.len as usize) {
                    Ok((true, Tls13Record::SIZE + rec.len as usize))
                } else {
                    Ok((false, (Tls13Record::SIZE + rec.len as usize) - deser.available()))
                }
            }
            Err(Mutter::DeserializationBufferInsufficient) => {
                Ok((false, Tls13Record::SIZE - deser.available()))
            }
            _ => Err(())
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tls13Ciphertext {
    opaque_type: RecordContentType, // u8
    ver: ProtoColVersion, // u16
    len: u16
}

#[allow(dead_code)]
impl Default for Tls13Ciphertext {
    fn default() -> Self {
        Self {
            opaque_type: RecordContentType::ApplicationData,
            ver: TlsLegacyVersion03003 as u16,
            len: 0
        }
    }
}

impl Tls13Ciphertext {
    pub const SIZE: usize = 5;
}

impl BufferSniffer for Tls13Ciphertext {
    fn sniff(deser: &DeSer) -> Result<(bool, usize), ()> {
        if !deser.have(Self::SIZE) {
            return Ok((false, Self::SIZE - deser.available()))
        }
        if RecordContentType::ApplicationData as u8 != deser.peek_u8() {
            log::error!("Error - expecting cipher text application data header - {}", deser.peek_u8());
            return Err(())
        }
        if deser.peek_u16_at(1) != TlsLegacyVersion03003 as u16 {
            log::error!("Error - expecting cipher text legacy tls version (0x0303)");
            return Err(())
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

impl BufferSniffer for Tls13InnerPlaintext {
    fn sniff(deser: &DeSer) -> Result<(bool, usize), ()> {
        Ok((true, deser.len()))
    }
}

pub struct DHSession {
    x25519_key_pair: X25519KeyPair,
    p256_key_pair: P256KeyPair,
}

#[allow(dead_code)]
impl DHSession {
    pub fn new() -> Self {
        Self {
            x25519_key_pair: X25519KeyPair::default(),
            p256_key_pair: P256KeyPair::default(),
        }
    }

    pub fn x25519_key_share(&mut self) -> KeyShare {
        KeyShare::x25519(self.x25519_key_pair.public_bytes())
    }

    pub fn p256_key_share(&mut self) -> KeyShare {
        KeyShare::secp256r1(self.p256_key_pair.public_bytes().as_bytes())
    }

    pub fn x25519_dh(self, pk: Vec<u8>) -> Vec<u8> {
        let dh_res = self.x25519_key_pair.dh(pk.try_into().unwrap());
        dh_res.to_bytes().as_slice().to_vec()
    }

    pub fn p256_dh(self, pk: Vec<u8>) -> Vec<u8> {
        let dh_res = self.p256_key_pair.dh(&pk).unwrap();
        dh_res.raw_secret_bytes().as_slice().to_vec()
    }
}

pub struct Tls13ProtocolSession {
    pub(crate) serv_stream: TlsStream,
    random: Vec<u8>,
    msg_ctx: Vec<u8>,
    hs_buf: Vec<u8>,
    serv_hello_rec_size: usize,
    hs_buf_last: usize,
}

#[allow(dead_code)]
impl Tls13ProtocolSession {
    pub const RECORD_HEADER_LEN: usize = 5;
    pub const LEGACY_VER_0X0303: u16 = 0x0303;
    pub const REC_SIZE_MAX: usize = 1 << 14;
    pub const MSG_SIZE_MAX: u32 = 1 << 14;

    pub fn new(serv_stream: TlsStream) -> Self {
        Self {
            serv_stream,
            random: crypto::CryptoRandom::<32>::bytes().to_vec(),
            msg_ctx: vec![],
            hs_buf: vec![],
            serv_hello_rec_size: 0,
            hs_buf_last: 0,
        }
    }

    pub fn random(&mut self) -> [u8; 32] {
        self.random.clone().try_into().unwrap()
    }

    pub fn msg_ctx(&self) -> Vec<u8> {
        self.msg_ctx.clone()
    }

    pub fn update_msg_ctx(&mut self, bytes: Vec<u8>) {
        self.msg_ctx.extend(bytes)
    }

    pub fn client_hello(&mut self, ch: &ClientHelloMsg) -> Result<(), Mutter> {
        let mut ch_msg = vec![0; ch.size()];
        ch.serialize(&mut ch_msg)?;
        let _n = self.serv_stream.write(&ch_msg)?;
        assert_eq!(_n, ch.size());

        self.msg_ctx.extend_from_slice(&ch_msg[Tls13Record::SIZE..ch.size()]);

        Ok(())
    }

    pub fn read_server_hello(&mut self) -> Result<ServerHelloMsg, Mutter> {
        self.hs_buf = Vec::new();
        if !try_sniff::<Tls13Record>(Tls13Record::SIZE, &mut self.hs_buf, &mut self.serv_stream) {
            log::error!("Bad handshake record - expecting ServerHello.");
            return Mutter::ExpectingServerHello.into()
        }
        let mut deser = DeSer::new(&self.hs_buf);
        let (sh, off) = ServerHelloMsg::deserialize(&mut deser).unwrap();
        assert_eq!(off, Tls13Record::SIZE);
        self.serv_hello_rec_size = Tls13Record::SIZE + sh.fragment_len as usize;
        self.hs_buf_last = self.serv_hello_rec_size;
        // log::info!("{:?}", sh);
        self.msg_ctx.extend_from_slice(&self.hs_buf[Tls13Record::SIZE..self.serv_hello_rec_size]);

        log::info!("ServerHello - Validated");
        Ok(sh)
    }

    fn hs_buf_available(&self) -> usize {
        assert!(self.hs_buf_last <= self.hs_buf.len());
        self.hs_buf.len() - self.hs_buf_last
    }

    pub fn read_change_cipher_spec(&mut self) -> Result<usize, Mutter> {
        if self.hs_buf_available() < Tls13Record::SIZE + 1 {
            if !try_sniff::<Tls13Record>(Tls13Record::SIZE + 1, &mut self.hs_buf, &mut self.serv_stream) {
                return Mutter::ExpectingChangeCipherSpec.into()
            }
        }
        let mut deser = DeSer::new(&self.hs_buf[self.hs_buf_last..]);
        if let Some((_, size)) = ChangeCipherSpecMsg::deserialize(&mut deser)? {
            log::info!("ChangeCipherSpec - Found");
            self.hs_buf_last += size;
        } else {
            log::info!("ChangeCipherSpec - Not Found");
        }
        Ok(0)
    }

    pub fn read_ciphertext_record(&mut self) -> Result<Vec<u8>, Mutter> {
        let start = self.hs_buf_last;
        // log::info!("read_ciphertext_record - available = {}", self.hs_buf_available());
        if self.hs_buf_available() < Tls13Ciphertext::SIZE {
            let need = Tls13Ciphertext::SIZE - self.hs_buf_available();
            if !try_sniff::<Tls13Ciphertext>(need, &mut self.hs_buf, &mut self.serv_stream) {
                return Mutter::ExpectingCiphertextRecord.into()
            }
        }
        let len = {
            let p = &self.hs_buf[self.hs_buf_last..];
            let deser = DeSer::new(p);
            assert_eq!(deser.peek_u8(), 23);
            assert_eq!(deser.peek_u16_at(1), 0x0303);
            deser.peek_u16_at(3) as usize
        };
        assert!(len > 0);

        if self.hs_buf_available() < Tls13Ciphertext::SIZE + len {
            let need = Tls13Ciphertext::SIZE + len - self.hs_buf_available();
            if !try_sniff::<Tls13InnerPlaintext>(need, &mut self.hs_buf, &mut self.serv_stream) {
                return Mutter::ExpectingCiphertextRecord.into()
            }
        }

        let ct = &self.hs_buf[start..start + Tls13Ciphertext::SIZE + len];
        self.hs_buf_last += Tls13Ciphertext::SIZE + len;

        Ok(ct.into())
    }

    pub fn create_handshake_secrets(&self,
                                    cipher_suite: CipherSuite,
                                    serv_key_share: KeyShare,
                                    dh: DHSession) -> Result<HandshakeSecrets, Mutter> {
        let dh_shared_secret: Vec<u8> =
            if serv_key_share.group == SupportedGroup::X25519 {
                dh.x25519_dh(serv_key_share.public_key)
            } else if serv_key_share.group == SupportedGroup::Secp256r1 {
                dh.p256_dh(serv_key_share.public_key)
            } else {
                vec![]
            };

        assert!(!dh_shared_secret.is_empty());

        let hs_cipher_suite: Box<dyn TlsCipherSuite> = cipher_suite.try_into()?;

        let secrets = hs_cipher_suite.derive_handshake_secrets(&dh_shared_secret, &self.msg_ctx);

        let serv_cipher = hs_cipher_suite.cipher(secrets.1.clone(), secrets.2.clone());
        let cl_cipher = hs_cipher_suite.cipher(secrets.4.clone(), secrets.5.clone());

        Ok(HandshakeSecrets::new(
            hs_cipher_suite,
            secrets.0,
            serv_cipher,
            secrets.3,
            cl_cipher,
            secrets.6))
    }
}

pub trait BufferSniffer {
    fn sniff(deser: &DeSer) -> Result<(bool, usize), ()>;
}

pub fn try_sniff<S: BufferSniffer>(need: usize, tls_buf: &mut Vec<u8>, serv_stream: &mut TlsStream) -> bool {
    let mut require = need;
    let mut cache = vec![0; 0];
    while require > 0 {
        match serv_stream.fulfill(require, &mut cache) {
            Ok(_) => {
                let deser = DeSer::new(&cache);
                if let Ok((adequate, size)) = S::sniff(&deser) {
                    if adequate {
                        tls_buf.extend(cache);
                        return true
                    } else {
                        require = size
                    }
                } else {
                    log::error!("try_buf_sniff - cannot sniff.");
                    return false
                }
            }
            Err(e) => {
                log::error!("try_buf_sniff - Error {:#?}", e);
                return false
            }
        }
    }
    false
}