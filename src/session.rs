use crate::ccs::ChangeCipherSpecMsg;
use crate::cert::{CertificateMsg, CertificateVerifyMsg};
use crate::ch::ClientHelloMsg;
use crate::cipher::{AppTrafficSecrets, HandshakeSecrets, TlsCipherSuite};
use crate::def::{CipherSuiteId, HandshakeType, RecordContentType, SupportedGroup};
use crate::deser::DeSer;
use crate::ecdhe::DHSession;
use crate::enc_ext::EncryptedExtensionsMsg;
use crate::err::Mutter;
use crate::ext::ServerSessionPublicKey;
use crate::fin::FinishedMsg;
use crate::rand;
use crate::rec::{try_fetch, Tls13Ciphertext, Tls13InnerPlaintext, Tls13Record};
use crate::sh::ServerHelloMsg;
use crate::stream::{Stream, TlsStream};

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
            random: rand::CryptoRandom::<32>::bytes().to_vec(),
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
        if !try_fetch::<Tls13Record>(
            &mut self.serv_stream,
            &mut self.hello_msg_buf,
            Tls13Record::SIZE,
        ) {
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

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum AuthMsgType {
    EncExt(EncryptedExtensionsMsg),
    Cert(CertificateMsg),
    CertVerify(CertificateVerifyMsg),
    Fin(FinishedMsg),
}

// On success, returns the plaintext message bytes as the transcript
pub(crate) trait AuthProc {
    fn authenticate(
        deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Mutter>;
}

pub struct AuthenticationSession {
    serv_stream: TlsStream,
    msg_ctx: Vec<u8>,
    hs_msg_buf: Vec<u8>,
    ciphertext_rec_end: usize,
    secrets: HandshakeSecrets,
}

impl AuthProc for EncryptedExtensionsMsg {
    fn authenticate(
        mut deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Mutter> {
        EncryptedExtensionsMsg::deserialize(&mut deser)
            .map(|(enc_ext_msg, msg_slice)| {
                if deser.peek_u8() == RecordContentType::Handshake as u8 {
                    deser.ru8();
                    log::info!("EncryptedExtensions - ContentType = HANDSHAKE");
                }
                (enc_ext_msg, msg_slice)
            })
            .map(|(enc_ext_msg, msg_slice)| {
                log::info!("EncryptedExtensions");
                session.update_msg_ctx(&msg_slice);
                (AuthMsgType::EncExt(enc_ext_msg), msg_slice)
            })
    }
}

impl AuthProc for FinishedMsg {
    fn authenticate(
        mut deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Mutter> {
        FinishedMsg::deserialize(&mut deser).and_then(|(serv_fin_msg, msg_slice)| {
            // verify the MAC in the Server Finished message
            session
                .server_finished_mac()
                .and_then(|expected_tag| match serv_fin_msg.check_mac(expected_tag) {
                    Ok(_) => Ok((serv_fin_msg, msg_slice)),
                    Err(e) => Err(e),
                })
                .map_err(|e| {
                    log::error!("ServerFinished - Invalid Tag!");
                    e
                })
                .and_then(|res| {
                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                        deser.ru8();
                        Ok(res)
                    } else {
                        Mutter::MissingInnerPlaintextContentType.into()
                    }
                })
                .map_err(|e| {
                    log::info!("ServerFinished - error {e:#?}");
                    e
                })
                .map(|(fin_msg, msg_slice)| {
                    // include server finished message in the msg_ctx
                    log::info!("ServerFinished - Verified!");
                    session.update_msg_ctx(&msg_slice);
                    (AuthMsgType::Fin(fin_msg), msg_slice)
                })
        })
    }
}

impl AuthProc for CertificateMsg {
    fn authenticate(
        mut deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Mutter> {
        CertificateMsg::deserialize(&mut deser)
            .map(|(cert_msg, msg_slice)| {
                if deser.peek_u8() == RecordContentType::Handshake as u8 {
                    deser.ru8();
                    log::info!("Certificate - ContentType = HANDSHAKE");
                }
                (cert_msg, msg_slice)
            })
            .map(|(cert_msg, msg_slice)| {
                log::info!("Certificate ({} bytes)", msg_slice.len());
                session.update_msg_ctx(&msg_slice);
                (AuthMsgType::Cert(cert_msg), msg_slice)
            })
    }
}

impl AuthProc for CertificateVerifyMsg {
    fn authenticate(
        mut deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Mutter> {
        CertificateVerifyMsg::deserialize(&mut deser)
            .map(|(cert_verify_msg, msg_slice)| {
                if deser.peek_u8() == RecordContentType::Handshake as u8 {
                    deser.ru8();
                    log::info!("CertificateVerify - ContentType = HANDSHAKE");
                }
                (cert_verify_msg, msg_slice)
            })
            .map(|(cert_verify_msg, msg_slice)| {
                log::info!("CertificateVerify");
                session.update_msg_ctx(&msg_slice);
                (AuthMsgType::CertVerify(cert_verify_msg), msg_slice)
            })
    }
}

type MsgAuthResult = Result<(AuthMsgType, Vec<u8>), Mutter>;

type MsgAuthProc = fn(&mut DeSer, &mut AuthenticationSession) -> MsgAuthResult;

type MsgTypeAuthProcs = [(HandshakeType, MsgAuthProc); 4];

pub struct MessageAuthenticator<'a> {
    deser: DeSer<'a>,
    proc: usize,
}

impl<'a> Default for MessageAuthenticator<'a> {
    fn default() -> Self {
        Self {
            deser: DeSer::new(&[]),
            proc: 0,
        }
    }
}

impl<'a> MessageAuthenticator<'a> {
    const MSG_TYPE_AUTH_PROCS: MsgTypeAuthProcs = [
        (HandshakeType::EncryptedExtensions, |d, s| {
            EncryptedExtensionsMsg::authenticate(d, s)
        }),
        (HandshakeType::Certificate, |d, s| {
            CertificateMsg::authenticate(d, s)
        }),
        (HandshakeType::CertificateVerify, |d, s| {
            CertificateVerifyMsg::authenticate(d, s)
        }),
        (HandshakeType::Finished, |d, s| {
            FinishedMsg::authenticate(d, s)
        }),
    ];

    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            deser: DeSer::new(&buf),
            proc: 0,
        }
    }

    pub fn forward(self, buf: &'a [u8]) -> Self {
        Self {
            deser: DeSer::new(&buf),
            proc: self.proc,
        }
    }

    pub fn finished(&self) -> bool {
        self.pos() == Self::MSG_TYPE_AUTH_PROCS.len()
    }

    pub fn plaintext(&self) -> Option<()> {
        if self.deser.available() > 0 {
            Some(())
        } else {
            None
        }
    }

    pub fn authenticate_next(&mut self, session: &mut AuthenticationSession) -> MsgAuthResult {
        assert!(self.pos() < Self::MSG_TYPE_AUTH_PROCS.len());
        (
            self.auth_proc()(&mut self.deser, session),
            self.update_proc(),
        )
            .0
    }

    fn auth_proc(&self) -> MsgAuthProc {
        Self::MSG_TYPE_AUTH_PROCS[self.pos()].1
    }

    fn pos(&self) -> usize {
        assert!(self.proc <= Self::MSG_TYPE_AUTH_PROCS.len());
        self.proc
    }

    fn update_proc(&mut self) {
        assert!(self.proc < Self::MSG_TYPE_AUTH_PROCS.len());
        self.proc += 1
    }

    pub fn authenticate(session: &mut AuthenticationSession) -> bool {
        let mut authenticator = Self::default();
        while !authenticator.finished() {
            let ciphertext_rec = session
                .read_ciphertext_record()
                .expect("handshake message ciphertext");
            // decrypt and cache TlsInnerPlaintext records
            let ad = ciphertext_rec[0..5].to_vec();
            let mut dec_data_buf = ciphertext_rec[5..].to_vec();
            session
                .decrypt_next(&ad, &mut dec_data_buf)
                .expect("decrypted handshake data");
            assert!(dec_data_buf.len() < ciphertext_rec.len() - 5);

            // iterate and process each inner_plaintext_rec in the cache
            authenticator = authenticator.forward(dec_data_buf.leak());
            while authenticator.plaintext().is_some() {
                let _res = authenticator.authenticate_next(session);
            }
        }
        true
    }
}

impl AuthenticationSession {
    pub fn receive(&mut self, size: usize, mut data: &mut Vec<u8>) -> Result<usize, Mutter> {
        self.serv_stream.read(size, &mut data)
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize, Mutter> {
        self.serv_stream.write(data)
    }

    pub fn update_msg_ctx(&mut self, bytes: &Vec<u8>) {
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
            if !try_fetch::<Tls13Ciphertext>(&mut self.serv_stream, &mut self.hs_msg_buf, need) {
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

    pub fn send_client_finished(&mut self) -> Result<usize, Mutter> {
        // opaque verify data
        self.client_finished_mac()
            .map(|verify_data| {
                assert_eq!(verify_data.len(), self.digest_size());
                FinishedMsg::serialize(verify_data)
            })
            .and_then(|mut fin_msg| {
                // aad must account for the size of the fin message + 16 bytes AEAD authentication tag
                self.encrypt_next(
                    &Tls13Ciphertext::aad(fin_msg.len() as u16 + 16),
                    &mut fin_msg,
                )?;
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
    pos: usize,
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
            0x03,
            0x03, // legacy record version
            l1,
            l2, // length of the inner plaintext in big-endian
        ]
        .into();

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
            if !try_fetch::<Tls13Ciphertext>(&mut self.serv_stream, &mut self.buf, need) {
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
            return Ok(0);
        }

        if self.buf_available() < Tls13Ciphertext::SIZE + len {
            let need = Tls13Ciphertext::SIZE + len - self.buf_available();
            if !try_fetch::<Tls13InnerPlaintext>(&mut self.serv_stream, &mut self.buf, need) {
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
