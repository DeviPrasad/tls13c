use crate::ccs::ChangeCipherSpecMsg;
use crate::cert::{CertificateMsg, CertificateVerifyMsg};
use crate::ch::ClientHelloMsg;
use crate::cipher::{AppTrafficSecrets, HandshakeSecrets, TlsCipherSuite, TranscriptHash};
use crate::def::{
    CipherSuiteId, HandshakeType, RecordContentType, SignatureScheme, SupportedGroup,
};
use crate::deser::DeSer;
use crate::ecdhe::DHSession;
use crate::enc_ext::EncryptedExtensionsMsg;
use crate::err::Error;
use crate::ext::ServerPublicKey;
use crate::fin::FinishedMsg;
use crate::rec::{try_fetch, Tls13Ciphertext, Tls13InnerPlaintext, Tls13Record};
use crate::sh::ServerHelloMsg;
use crate::stream::{Stream, TlsStream};
use x509_cert::Certificate;

pub struct KeyExchangeSession {
    server_stream: TlsStream,
    msg_ctx: Vec<u8>,
    msg_buf: Vec<u8>,
    cursor: usize,
}

#[allow(dead_code)]
impl KeyExchangeSession {
    pub const RECORD_HEADER_LEN: usize = 5;
    pub const LEGACY_VER_0X0303: u16 = 0x0303;
    pub const REC_SIZE_MAX: usize = 1 << 14;
    pub const MSG_SIZE_MAX: u32 = 1 << 14;

    pub fn new(serv_stream: TlsStream) -> Self {
        Self {
            server_stream: serv_stream,
            msg_ctx: vec![],
            msg_buf: vec![],
            cursor: 0,
        }
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.server_stream.write(data)
    }

    pub fn send_client_hello(&mut self, ch: &ClientHelloMsg) -> Result<(), Error> {
        let mut ch_msg = vec![0; ch.size()];
        ch.serialize(&mut ch_msg)?;
        let _n = self.server_stream.write(&ch_msg)?;
        assert_eq!(_n, ch.size());

        self.msg_ctx.extend(&ch_msg[Tls13Record::SIZE..ch.size()]);

        Ok(())
    }

    pub fn receive_server_hello(&mut self) -> Result<ServerHelloMsg, Error> {
        self.msg_buf = Vec::new();
        if !try_fetch::<Tls13Record>(
            &mut self.server_stream,
            &mut self.msg_buf,
            Tls13Record::SIZE,
        ) {
            log::error!("Bad handshake record - expecting ServerHello.");
            return Error::ExpectingServerHello.into();
        }
        let mut deser = DeSer::new(&self.msg_buf);

        // check if the server has raised an alert.
        // RFC 8446, Section 6. Alert Protocol, pages 85-86.
        if deser.peek_u8() == RecordContentType::Alert as u8 {
            if deser.peek_u8_at(5) == 2 {
                // Fatal Error
                return match deser.peek_u8_at(6) {
                    0 => Error::AlertCloseNotify.into(),
                    40 => Error::AlertHandshakeFailure.into(),
                    47 => Error::AlertIllegalParameter.into(),
                    109 => Error::AlertMissingExtension.into(),
                    110 => Error::AlertUnsupportedExtension.into(),
                    112 => Error::AlertUnrecognizedName.into(),
                    _ => Error::AlertGeneric.into(),
                };
            } else {
                deser.seek(7); // skip past the alert
            }
        }

        let (sh, _) = ServerHelloMsg::deserialize(&mut deser)?;
        self.cursor = Tls13Record::SIZE + sh.fragment_len as usize;
        self.msg_ctx
            .extend(&self.msg_buf[Tls13Record::SIZE..self.cursor]);
        log::info!("ServerHello - Validated");
        Ok(sh)
    }

    fn hs_buf_available(&self) -> usize {
        assert!(self.cursor <= self.msg_buf.len());
        self.msg_buf.len() - self.cursor
    }

    pub fn read_optional_change_cipher_spec(&mut self) -> Result<usize, Error> {
        if self.hs_buf_available() < Tls13Record::SIZE + 1
            && !try_fetch::<Tls13Record>(
                &mut self.server_stream,
                &mut self.msg_buf,
                Tls13Record::SIZE + 1,
            )
        {
            return Error::ExpectingChangeCipherSpec.into();
        }
        let mut deser = DeSer::new(&self.msg_buf[self.cursor..]);
        if let Some((_, size)) = ChangeCipherSpecMsg::deserialize(&mut deser)? {
            log::info!("ChangeCipherSpec - Found");
            self.cursor += size;
        } else {
            log::info!("ChangeCipherSpec - Not Found");
        }
        Ok(0)
    }

    pub fn to_authentication_session(
        self,
        cipher_suite_id: CipherSuiteId,
        serv_key: ServerPublicKey,
        dh: DHSession,
        sig_algs: Vec<SignatureScheme>,
    ) -> Result<AuthenticationSession, Error> {
        let dh_shared_secret = if serv_key.group == SupportedGroup::X25519 {
            dh.x25519_dh(serv_key.public_key)
        } else if serv_key.group == SupportedGroup::Secp256r1 {
            dh.p256_dh(serv_key.public_key)
        } else {
            return Error::EmptyDHSecret.into();
        };

        assert!(!dh_shared_secret.is_empty());

        let cipher_suite: Box<dyn TlsCipherSuite> = cipher_suite_id.try_into()?;

        let secrets = cipher_suite.handshake_traffic_secrets(&dh_shared_secret, &self.msg_ctx);

        let server_cipher = cipher_suite.cipher(secrets.1.clone(), secrets.2.clone());
        let client_cipher = cipher_suite.cipher(secrets.4.clone(), secrets.5.clone());

        let secrets = HandshakeSecrets::new(
            cipher_suite_id,
            cipher_suite,
            secrets.0,
            server_cipher,
            secrets.3,
            client_cipher,
            secrets.6,
        );

        Ok(AuthenticationSession {
            serv_stream: self.server_stream,
            msg_ctx: self.msg_ctx,
            hs_msg_buf: self.msg_buf[self.cursor..].into(),
            ciphertext_rec_end: 0,
            secrets,
            sig_algs,
            cert: None,
        })
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
enum AuthMsgType {
    EncExt(EncryptedExtensionsMsg),
    Cert(CertificateMsg),
    CertVerify(CertificateVerifyMsg),
    Fin(FinishedMsg),
}

// On success, returns the plaintext message bytes as the transcript
trait AuthProc {
    fn authenticate(
        deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Error>;
}

pub struct AuthenticationSession {
    serv_stream: TlsStream,
    msg_ctx: Vec<u8>,
    hs_msg_buf: Vec<u8>,
    ciphertext_rec_end: usize,
    secrets: HandshakeSecrets,
    sig_algs: Vec<SignatureScheme>,
    cert: Option<Certificate>,
}

impl AuthProc for EncryptedExtensionsMsg {
    fn authenticate(
        deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Error> {
        EncryptedExtensionsMsg::deserialize(deser)
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

impl AuthProc for CertificateMsg {
    fn authenticate(
        deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Error> {
        CertificateMsg::deserialize(deser)
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
                session.cert = cert_msg.certificate();
                (AuthMsgType::Cert(cert_msg), msg_slice)
            })
    }
}

impl AuthProc for CertificateVerifyMsg {
    fn authenticate(
        deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Error> {
        CertificateVerifyMsg::deserialize(deser)
            .map(|(cert_verify_msg, msg_slice)| {
                if deser.peek_u8() == RecordContentType::Handshake as u8 {
                    deser.ru8();
                    log::info!("CertificateVerify - ContentType = HANDSHAKE");
                }
                (cert_verify_msg, msg_slice)
            })
            .and_then(|(cert_verify_msg, msg_slice)| {
                if cert_verify_msg.supported_sig_scheme(&session.sig_algs) {
                    let cert = session
                        .cert
                        .clone()
                        .ok_or(Error::UnsupportedSignatureScheme)?;
                    let transcript_hash = session.server_certificate_verify_hash()?;
                    cert_verify_msg.verify(transcript_hash, cert)?;
                    Ok((cert_verify_msg, msg_slice))
                } else {
                    Error::UnsupportedSignatureSchemeInCertificateVerify.into()
                }
            })
            .map(|(cert_verify_msg, msg_slice)| {
                session.update_msg_ctx(&msg_slice);
                (AuthMsgType::CertVerify(cert_verify_msg), msg_slice)
            })
    }
}

impl AuthProc for FinishedMsg {
    fn authenticate(
        deser: &mut DeSer,
        session: &mut AuthenticationSession,
    ) -> Result<(AuthMsgType, Vec<u8>), Error> {
        FinishedMsg::deserialize(deser).and_then(|(serv_fin_msg, msg_slice)| {
            // RFC 8446, Page 62.
            // verify the MAC in the Server Finished message. The MAC is over the value
            // Transcript-Hash(Handshake Context, Certificate, CertificateVerify)
            // using a MAC key derived from the Base Key (server_handshake_traffic_ secret)
            session
                .server_finished_mac()
                .and_then(|expected_tag| match serv_fin_msg.check_mac(expected_tag) {
                    Ok(_) => Ok((serv_fin_msg, msg_slice)),
                    Err(e) => Err(e),
                })
                .and_then(|res| {
                    if deser.peek_u8() == RecordContentType::Handshake as u8 {
                        deser.ru8();
                        Ok(res)
                    } else {
                        Error::MissingInnerPlaintextContentType.into()
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
                    //let h = tx_hash.hash();
                    (AuthMsgType::Fin(fin_msg), msg_slice)
                })
        })
    }
}

type MsgAuthResult = Result<(AuthMsgType, Vec<u8>), Error>;

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

    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self {
            deser: DeSer::new(buf),
            proc: pos,
        }
    }

    fn finished(pos: usize) -> bool {
        pos >= Self::MSG_TYPE_AUTH_PROCS.len()
    }

    fn plaintext(&self) -> Option<()> {
        if self.deser.available() > 0 {
            Some(())
        } else {
            None
        }
    }

    fn authenticate_next(&mut self, session: &mut AuthenticationSession) -> MsgAuthResult {
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

    pub fn authenticate(session: &mut AuthenticationSession) -> Result<(), Error> {
        let mut pos = 0;
        let mut tx_hash: Box<dyn TranscriptHash> =
            session.secrets.tls_cipher_suite_name.try_into()?;
        tx_hash.update(&session.msg_ctx);
        while !MessageAuthenticator::finished(pos) {
            let ciphertext_rec = session.read_ciphertext_record()?;
            log::info!("Read ciphertext record {} of size {} bytes", pos + 1, ciphertext_rec.len());
            // decrypt and cache TlsInnerPlaintext records
            let aad = ciphertext_rec[0..5].to_vec();
            let mut dec_data_buf = ciphertext_rec[5..].to_vec();
            session.decrypt_next(&aad, &mut dec_data_buf)?;
            // 16 bytes of authentication tag + 5 bytes of aad
            assert_eq!(dec_data_buf.len(), ciphertext_rec.len() - (16 + aad.len()));

            // iterate and process each inner_plaintext_rec in the cache
            let mut auth = MessageAuthenticator::new(&dec_data_buf, pos);
            while auth.plaintext().is_some() {
                if let Err(e) = auth.authenticate_next(session) {
                    log::error!("Fragmented record across ciphertext boundaries in a flight");
                    return e.into();
                }
            }
            pos = auth.pos();
        }
        Ok(())
    }
}

impl AuthenticationSession {
    fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.serv_stream.write(data)
    }

    fn update_msg_ctx(&mut self, msg: &[u8]) {
        self.msg_ctx.extend(msg);
    }

    fn digest_size(&self) -> usize {
        self.secrets.digest_size()
    }

    fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.secrets.decrypt_next(ad, out)
    }

    fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.secrets.encrypt_next(ad, out)
    }

    fn hs_buf_available(&self) -> usize {
        assert!(self.ciphertext_rec_end <= self.hs_msg_buf.len());
        self.hs_msg_buf.len() - self.ciphertext_rec_end
    }

    fn read_ciphertext_record(&mut self) -> Result<Vec<u8>, Error> {
        let start = self.ciphertext_rec_end;
        if self.hs_buf_available() < Tls13Ciphertext::SIZE {
            let need = Tls13Ciphertext::SIZE - self.hs_buf_available();
            if !try_fetch::<Tls13Ciphertext>(&mut self.serv_stream, &mut self.hs_msg_buf, need) {
                return Error::ExpectingCiphertextRecord.into();
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
                return Error::ExpectingCiphertextRecord.into();
            }
        }

        let ct = &self.hs_msg_buf[start..start + Tls13Ciphertext::SIZE + len];
        self.ciphertext_rec_end += Tls13Ciphertext::SIZE + len;

        Ok(ct.into())
    }

    pub fn send_client_finished(&mut self) -> Result<usize, Error> {
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

    fn server_finished_mac(&self) -> Result<Vec<u8>, Error> {
        self.secrets.server_finished_mac(&self.msg_ctx)
    }

    fn server_certificate_verify_hash(&mut self) -> Result<Vec<u8>, Error> {
        self.secrets.server_certificate_verify_hash(&self.msg_ctx)
    }

    fn client_finished_mac(&self) -> Result<Vec<u8>, Error> {
        self.secrets.client_finished_mac(&self.msg_ctx)
    }

    pub fn app_session(self) -> Result<AppSession, Error> {
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
    serv_stream: TlsStream,
    secrets: AppTrafficSecrets,
    buf: Vec<u8>,
    pos: usize,
}

impl AppSession {
    fn send_ciphertext(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.serv_stream.write(data)
    }

    fn decrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.secrets.decrypt_next(ad, out)
    }

    fn encrypt_next(&mut self, ad: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.secrets.encrypt_next(ad, out)
    }

    fn buf_available(&self) -> usize {
        assert!(self.pos <= self.buf.len());
        self.buf.len() - self.pos
    }

    pub(crate) fn read_ciphertext_record(&mut self, data: &mut Vec<u8>) -> Result<usize, Error> {
        if self.buf_available() < Tls13Ciphertext::SIZE {
            let need = Tls13Ciphertext::SIZE - self.buf_available();
            if !try_fetch::<Tls13Ciphertext>(&mut self.serv_stream, &mut self.buf, need) {
                return Error::ExpectingCiphertextRecord.into();
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
                return Error::ExpectingCiphertextRecord.into();
            }
        }

        let aad = self.buf[self.pos..self.pos + 5].to_vec();
        let mut decrypted = self.buf[self.pos + 5..self.pos + 5 + len].to_vec();
        self.pos += Tls13Ciphertext::SIZE + len;
        self.decrypt_next(&aad, &mut decrypted)?;

        data.extend(&decrypted);
        Ok(decrypted.len())
    }

    // plaintext 'data' is encrypted and sent.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
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

    pub fn read(&mut self, data: &mut Vec<u8>) -> Result<usize, Error> {
        self.read_ciphertext_record(data)
    }

    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.serv_stream.shutdown()
    }
}
