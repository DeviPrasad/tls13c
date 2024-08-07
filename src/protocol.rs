use crate::{crypto, def};
use crate::ccs::ChangeCipherSpecMsg;
use crate::ch::ClientHelloMsg;
use crate::cipher::{AppTrafficSecrets, HandshakeSecrets, TlsCipherSuite};
use crate::crypto::{P256KeyPair, X25519KeyPair};
use crate::def::{
    CipherSuiteId, LegacyRecordVersion, ProtoColVersion, RecordContentType, SupportedGroup,
};
use crate::def::LegacyTlsVersion::TlsLegacyVersion03003;
use crate::deser::DeSer;
use crate::err::Mutter;
use crate::ext::ServerSessionPublicKey;
use crate::fin::FinishedMsg;
use crate::sh::ServerHelloMsg;
use crate::sock::{Stream, TlsStream};

#[allow(dead_code)]
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
        return match Tls13Record::peek(&deser) {
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
        };
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

    pub fn x25519_key_share(&mut self) -> ServerSessionPublicKey {
        ServerSessionPublicKey::x25519(self.x25519_key_pair.public_bytes())
    }

    pub fn p256_key_share(&mut self) -> ServerSessionPublicKey {
        ServerSessionPublicKey::secp256r1(self.p256_key_pair.public_bytes().as_bytes())
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

pub struct KeyExchangeSession {
    pub(crate) serv_stream: TlsStream,
    random: Vec<u8>,
    msg_ctx: Vec<u8>,
    hello_msg_buf: Vec<u8>,
    hello_msg_end: usize,
}

#[allow(dead_code)]
impl KeyExchangeSession {
    pub const RECORD_HEADER_LEN: usize = 5;
    pub const LEGACY_VER_0X0303: u16 = 0x0303;
    pub const REC_SIZE_MAX: usize = 1 << 14;
    pub const MSG_SIZE_MAX: u32 = 1 << 14;

    pub fn new(serv_stream: TlsStream) -> Self {
        Self {
            serv_stream,
            random: crypto::CryptoRandom::<32>::bytes().to_vec(),
            msg_ctx: vec![],
            hello_msg_buf: vec![],
            hello_msg_end: 0,
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize, Mutter> {
        self.serv_stream.write(data)
    }

    pub fn random(&mut self) -> [u8; 32] {
        self.random.clone().try_into().unwrap()
    }

    pub fn update_msg_ctx(&mut self, bytes: Vec<u8>) {
        self.msg_ctx.extend(bytes)
    }

    pub fn client_hello(&mut self, ch: &ClientHelloMsg) -> Result<(), Mutter> {
        let mut ch_msg = vec![0; ch.size()];
        ch.serialize(&mut ch_msg)?;
        let _n = self.serv_stream.write(&ch_msg)?;
        assert_eq!(_n, ch.size());

        self.msg_ctx
            .extend_from_slice(&ch_msg[Tls13Record::SIZE..ch.size()]);

        Ok(())
    }

    pub fn read_server_hello(&mut self) -> Result<ServerHelloMsg, Mutter> {
        self.hello_msg_buf = Vec::new();
        if !try_fetch::<Tls13Record>(&mut self.serv_stream, &mut self.hello_msg_buf, Tls13Record::SIZE) {
            log::error!("Bad handshake record - expecting ServerHello.");
            return Mutter::ExpectingServerHello.into();
        }
        let mut deser = DeSer::new(&self.hello_msg_buf);
        let (sh, off) = ServerHelloMsg::deserialize(&mut deser).unwrap();
        assert_eq!(off, Tls13Record::SIZE);
        self.hello_msg_end = Tls13Record::SIZE + sh.fragment_len as usize;
        self.msg_ctx
            .extend_from_slice(&self.hello_msg_buf[Tls13Record::SIZE..self.hello_msg_end]);

        log::info!("ServerHello - Validated");
        Ok(sh)
    }

    fn hs_buf_available(&self) -> usize {
        assert!(self.hello_msg_end <= self.hello_msg_buf.len());
        self.hello_msg_buf.len() - self.hello_msg_end
    }

    pub fn read_change_cipher_spec(&mut self) -> Result<usize, Mutter> {
        if self.hs_buf_available() < Tls13Record::SIZE + 1 {
            if !try_fetch::<Tls13Record>(
                &mut self.serv_stream,
                &mut self.hello_msg_buf,
                Tls13Record::SIZE + 1,
            ) {
                return Mutter::ExpectingChangeCipherSpec.into();
            }
        }
        let mut deser = DeSer::new(&self.hello_msg_buf[self.hello_msg_end..]);
        if let Some((_, size)) = ChangeCipherSpecMsg::deserialize(&mut deser)? {
            log::info!("ChangeCipherSpec - Found");
            self.hello_msg_end += size;
        } else {
            log::info!("ChangeCipherSpec - Not Found");
        }
        Ok(0)
    }

    pub fn authentication_session(
        self,
        cipher_suite_id: CipherSuiteId,
        serv_key: ServerSessionPublicKey,
        dh: DHSession,
    ) -> Result<AuthenticationSession, Mutter> {
        let dh_shared_secret: Vec<u8> = if serv_key.group == SupportedGroup::X25519 {
            dh.x25519_dh(serv_key.public_key)
        } else if serv_key.group == SupportedGroup::Secp256r1 {
            dh.p256_dh(serv_key.public_key)
        } else {
            vec![]
        };

        assert!(!dh_shared_secret.is_empty());

        let cipher_suite: Box<dyn TlsCipherSuite> = cipher_suite_id.try_into()?;

        let secrets = cipher_suite.handshake_traffic_secrets(&dh_shared_secret, &self.msg_ctx);

        let serv_cipher = cipher_suite.cipher(secrets.1.clone(), secrets.2.clone());
        let cl_cipher = cipher_suite.cipher(secrets.4.clone(), secrets.5.clone());

        let secrets = HandshakeSecrets::new(
            cipher_suite_id,
            cipher_suite,
            secrets.0,
            serv_cipher,
            secrets.3,
            cl_cipher,
            secrets.6,
        );

        Ok(AuthenticationSession {
            serv_stream: self.serv_stream,
            msg_ctx: self.msg_ctx,
            hs_msg_buf: self.hello_msg_buf[self.hello_msg_end..].into(),
            ciphertext_rec_end: 0,
            secrets,
        })
    }
}

pub struct AuthenticationSession {
    serv_stream: TlsStream,
    msg_ctx: Vec<u8>,
    hs_msg_buf: Vec<u8>,
    ciphertext_rec_end: usize,
    secrets: HandshakeSecrets,
}

impl AuthenticationSession {
    pub fn receive(&mut self, size: usize, mut data: &mut Vec<u8>) -> Result<usize, Mutter> {
        self.serv_stream.read(size, &mut data)
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize, Mutter> {
        self.serv_stream.write(data)
    }

    pub fn update_msg_ctx(&mut self, bytes: Vec<u8>) {
        self.msg_ctx.extend(bytes)
    }

    pub fn digest_size(&self) -> usize {
        self.secrets.digest_size()
    }

    pub fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.secrets.decrypt_next(ad, out)
    }

    pub fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.secrets.encrypt_next(ad, out)
    }

    fn hs_buf_available(&self) -> usize {
        assert!(self.ciphertext_rec_end <= self.hs_msg_buf.len());
        self.hs_msg_buf.len() - self.ciphertext_rec_end
    }

    pub fn read_ciphertext_record(&mut self) -> Result<Vec<u8>, Mutter> {
        let start = self.ciphertext_rec_end;
        if self.hs_buf_available() < Tls13Ciphertext::SIZE {
            let need = Tls13Ciphertext::SIZE - self.hs_buf_available();
            if !try_fetch::<Tls13Ciphertext>(&mut self.serv_stream, &mut self.hs_msg_buf, need, ) {
                return Mutter::ExpectingCiphertextRecord.into();
            }
        }
        let len = {
            let p = &self.hs_msg_buf[self.ciphertext_rec_end..];
            let deser = DeSer::new(p);
            assert_eq!(deser.peek_u8(), 23);
            assert_eq!(deser.peek_u16_at(1), 0x0303);
            deser.peek_u16_at(3) as usize
        };
        assert!(len > 0);

        if self.hs_buf_available() < Tls13Ciphertext::SIZE + len {
            let need = Tls13Ciphertext::SIZE + len - self.hs_buf_available();
            if !try_fetch::<Tls13InnerPlaintext>(&mut self.serv_stream, &mut self.hs_msg_buf, need)
            {
                return Mutter::ExpectingCiphertextRecord.into();
            }
        }

        let ct = &self.hs_msg_buf[start..start + Tls13Ciphertext::SIZE + len];
        self.ciphertext_rec_end += Tls13Ciphertext::SIZE + len;

        Ok(ct.into())
    }

    pub fn send_client_finished_method(&mut self) -> Result<usize, Mutter> {
        // opaque verify data
        self.client_finished_mac()
            .map(|verify_data| {
                assert_eq!(verify_data.len(), self.digest_size());
                FinishedMsg::serialize(verify_data)
            })
            .and_then(|mut fin_msg| {
                // aad must account for the size of the fin message + 16 bytes AEAD authentication tag
                self.encrypt_next(&Tls13Ciphertext::aad(fin_msg.len() as u16 + 16), &mut fin_msg)?;
                Ok(fin_msg)
            })
            .and_then(|fin_msg| self.send(&Tls13Ciphertext::serialize(fin_msg)))
    }

    pub fn server_finished_mac(&self) -> Result<Vec<u8>, Mutter> {
        self.secrets.server_finished_mac(&self.msg_ctx)
    }

    pub fn client_finished_mac(&self) -> Result<Vec<u8>, Mutter> {
        self.secrets.client_finished_mac(&self.msg_ctx)
    }

    pub fn app_session(self) -> Result<AppSession, Mutter> {
        let hs_sec = &self.secrets;
        let traffic_cipher_suite: Box<dyn TlsCipherSuite> =
            hs_sec.tls_cipher_suite_name.try_into()?;
        let secrets = traffic_cipher_suite
            .derive_app_traffic_secrets(hs_sec.hs_traffic_secret_master(), &self.msg_ctx);
        let serv_cipher = traffic_cipher_suite.cipher(secrets.1.clone(), secrets.2.clone());
        let cl_cipher = traffic_cipher_suite.cipher(secrets.4.clone(), secrets.5.clone());

        let secrets = AppTrafficSecrets::new(
            hs_sec.tls_cipher_suite_name,
            traffic_cipher_suite,
            secrets.0,
            serv_cipher,
            secrets.3,
            cl_cipher,
            secrets.6,
        );

        Ok(AppSession {
            serv_stream: self.serv_stream,
            secrets,
            buf: vec![],
            pos: 0,
        })
    }
}

pub struct AppSession {
    pub(crate) serv_stream: TlsStream,
    secrets: AppTrafficSecrets,
    buf: Vec<u8>,
    pos: usize
}

impl AppSession {
    pub fn receive(&mut self, size: usize, mut data: &mut Vec<u8>) -> Result<usize, Mutter> {
        self.serv_stream.read(size, &mut data)
    }

    fn send_ciphertext(&mut self, data: &[u8]) -> Result<usize, Mutter> {
        self.serv_stream.write(data)
    }

    pub fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.secrets.decrypt_next(ad, out)
    }

    pub fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Mutter> {
        self.secrets.encrypt_next(ad, out)
    }

    // plaintext 'data' is encrypted and sent.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, Mutter> {
        let [l1, l2] = (data.len() as u16 + 16 + 1).to_be_bytes();
        // cipher text
        let mut ct: Vec<u8> = [
            RecordContentType::ApplicationData as u8,
            0x03, 0x03, // legacy record version
            l1, l2, // length of the inner plaintext in big-endian
        ].into();

        // copy data so we can encrypt it in place
        let mut enc_data = data.to_vec();
        enc_data.push(RecordContentType::ApplicationData as u8);
        self.encrypt_next(&ct[0..5], &mut enc_data)?;
        assert_eq!(enc_data.len(), data.len() + 16 + 1);
        ct.extend(enc_data);
        assert_eq!(ct.len(), data.len() + 16 + 5 + 1);

        self.send_ciphertext(&ct)
    }

    fn buf_available(&self) -> usize {
        assert!(self.pos <= self.buf.len());
        self.buf.len() - self.pos
    }

    pub fn read_ciphertext_record(&mut self, data: &mut Vec<u8>) -> Result<usize, Mutter> {
        if self.buf_available() < Tls13Ciphertext::SIZE {
            let need = Tls13Ciphertext::SIZE - self.buf_available();
            if !try_fetch::<Tls13Ciphertext>(&mut self.serv_stream, &mut self.buf, need, ) {
                return Mutter::ExpectingCiphertextRecord.into();
            }
        }
        let len = {
            let p = &self.buf[self.pos..];
            let deser = DeSer::new(p);
            assert_eq!(deser.peek_u8(), 23);
            assert_eq!(deser.peek_u16_at(1), 0x0303);
            deser.peek_u16_at(3) as usize
        };
        if len == 0 {
            return Ok(0)
        }

        if self.buf_available() < Tls13Ciphertext::SIZE + len {
            let need = Tls13Ciphertext::SIZE + len - self.buf_available();
            if !try_fetch::<Tls13InnerPlaintext>(&mut self.serv_stream, &mut self.buf, need)
            {
                return Mutter::ExpectingCiphertextRecord.into();
            }
        }

        let aad = self.buf[self.pos..self.pos + 5].to_vec();
        let mut decrypted = self.buf[self.pos + 5..self.pos + 5 + len].to_vec();
        self.pos += Tls13Ciphertext::SIZE + len;
        self.decrypt_next(&aad, &mut decrypted)?;

        data.extend(&decrypted);
        Ok(decrypted.len())
    }

    pub fn read(&mut self, data: &mut Vec<u8>) -> Result<usize, Mutter> {
        self.read_ciphertext_record(data)
    }

    pub fn shutdown(&mut self) -> Result<(), Mutter> {
        self.serv_stream.shutdown()
    }
}
