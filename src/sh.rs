use std::mem::size_of;

use crate::def::{
    CipherSuiteId, HandshakeType, LegacyRecordVersion, LegacyTlsVersion, Random, RecordContentType,
    SupportedGroup,
};
use crate::deser::DeSer;
use crate::err::Mutter;
use crate::ext::{ServerExtensions, ServerSessionPublicKey};
use crate::protocol::{KeyExchangeSession, Tls13Record};

#[allow(dead_code)]
pub struct ServerHelloDeSer {}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ServerHelloMsg {
    // TLSPlainText; page 79, sec 5.1. Record Layer
    rct: RecordContentType, // record content type - Handshake(22)
    // TLS 1.3 has deprecated the legacy record version indicator.
    // It MUST be set to 0x0303, and ignored for all practical purposes.
    legacy_rec_ver: LegacyRecordVersion, // legacy record version; value: u16 = 0x0303
    pub(crate) fragment_len: u16,
    // Handshake; Page 25, sec 4. Handshake Protocol
    ht: HandshakeType, // handshake type is ServerHello(2)
    pub(crate) len: u32,
    // ServerHello, page 31, sec 4.1.3. Server Hello
    legacy_tls_ver: LegacyTlsVersion, // value: u16 == 0x0303
    pub(crate) random: Random,
    // Echo of the contents of 'legacy_session_id' field from client's ClientHello message.
    pub(crate) legacy_session_id: Vec<u8>,
    // B.4. Cipher Suites. Dance with either AES or CHACHA20!
    // TlsAes128GcmSha256 (0x13, 0x01)
    // TlsAes256GcmSha384 (0x13, 0x02)
    // TLS_CHACHA20_POLY1305_SHA256 (0x13, 0x03)
    pub(crate) cipher_suite_id: CipherSuiteId,
    // TLS 1.3 client MUST send a vector [1, 0] for compression methods.
    // The TLS 1.3 server MUST echo the same value.
    legacy_compression_method: u8, // value == 0
    // ServerHello, page 32, sec 4.1.3. Server Hello
    // TLS 1.3 MUST contain the "supported_versions" extension.
    // It may contain either "pre_shared_key" or the "key_share" extension, or both.
    pub(crate) extensions: ServerExtensions,
}

#[allow(dead_code)]
impl ServerHelloMsg {
    pub fn deserialize(mut deser: &mut DeSer) -> Result<(ServerHelloMsg, usize), Mutter> {
        if !deser.have(Tls13Record::SIZE + size_of::<u32>()) {
            return Mutter::DeserializationBufferInsufficient.into();
        }
        let rec = Tls13Record::read_handshake(&mut deser)?;
        let sh_msg_start_cursor = deser.cursor();
        assert_eq!(deser.cursor(), 5);
        if HandshakeType::from(deser.ru8()) != HandshakeType::ServerHello {
            return Mutter::HandshakeType.into();
        }
        let msg_len: u32 = deser.ru24();
        if !(32..=KeyExchangeSession::MSG_SIZE_MAX).contains(&msg_len) {
            return Mutter::MsgLen.into();
        }
        // msg header would have consumed 4 bytes: 1 for message type and 3 for the fragment length
        // note that record length includes the msg header too.
        assert_eq!(rec.len as u32 - 4, msg_len);
        if !deser.cmp_u16(KeyExchangeSession::LEGACY_VER_0X0303) {
            return Mutter::LegacyTLS13MsgVer.into();
        }
        let read_server_random =
            |deser: &mut DeSer| deser.slice(32).try_into().map_err(|_| Mutter::RandomVal);
        let random: Random = read_server_random(&mut deser)?;
        let legacy_session_id: Vec<u8> = deser.vlu8_vec();
        let cipher_suite = CipherSuiteId::try_from(deser.ru16())?;
        let _compression_methods_ = deser.zlu8()?;

        let (extensions, _) = ServerExtensions::deserialize(deser)?;

        assert_eq!(deser.cursor() - 5, rec.len as usize);

        let sh = ServerHelloMsg {
            rct: rec.rct,
            legacy_rec_ver: rec.ver,
            // NOTE: this is the size of the entire HelloServer message. This is NOT msg_len!
            fragment_len: rec.len,
            ht: HandshakeType::ServerHello,
            len: msg_len,
            legacy_tls_ver: Default::default(),
            random,
            legacy_session_id,
            cipher_suite_id: cipher_suite,
            legacy_compression_method: 0,
            extensions,
        };

        Ok((sh, sh_msg_start_cursor))
    }

    pub fn key_share(
        &self,
        cl_key_shares: &[ServerSessionPublicKey],
    ) -> Result<ServerSessionPublicKey, Mutter> {
        let serv_key_share: ServerSessionPublicKey = self.extensions.0.clone();
        for client_key_share in cl_key_shares {
            if client_key_share.group == serv_key_share.group {
                if client_key_share.group == SupportedGroup::X25519 {
                    return Ok(serv_key_share);
                } else if client_key_share.group == SupportedGroup::Secp256r1 {
                    return Ok(serv_key_share);
                }
            }
        }
        Mutter::ServerKeyShareBad.into()
    }

    // sec 4.1.3 ServerHello, page 32
    // HelloRetryRequest messages uses the same structure as ServerHello, but with
    // Random set to the special value of the SHA-256 of "HelloRetryRequest".
    const HELLO_RETRY_REQUEST: &'static [u8] = &[
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];

    pub fn is_server_retry(&self) -> bool {
        self.random.eq(Self::HELLO_RETRY_REQUEST)
    }
}
