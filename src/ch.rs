use crate::def::{
    to_u16, CipherSuiteId, CipherSuites, HandshakeType, ProtoColVersion, Random, RecordContentType,
};
use crate::err::Mutter;
use crate::ext::{ClientExtensions, ServerSessionPublicKey};

struct CompressionMethods();

#[allow(dead_code)]
impl CompressionMethods {
    pub fn deserialize(bytes: &[u8]) -> Result<usize, Mutter> {
        if bytes.len() < 2 || !(bytes[0] == 1 && bytes[1] == 0) {
            return Err(Mutter::CompressionMethods);
        }
        Ok(2)
    }

    pub fn serialize(bytes: &mut [u8], pos: usize) -> usize {
        if bytes.len() < 2 {
            0
        } else {
            (bytes[pos], bytes[pos + 1]) = (1, 0);
            2
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ClientHelloMsg {
    // TLSPlainText; page 79, sec 5.1. Record Layer
    rct: RecordContentType, // record content type - Handshake(22)
    // TLS 1.3 has deprecated the legacy record version indicator.
    // It MUST be set to 0x0303, and ignored for all practical purposes.
    legacy_rec_ver: ProtoColVersion, // lvalue: u16 = 0x0303
    fragment_len: u16,
    // Handshake; Page 25, sec 4. Handshake Protocol
    ht: HandshakeType, // handshake type is ClientHello(1)
    len: u32,
    // ClientHello, page 28, sec 4.1.2. Client Hello
    legacy_tls_ver: ProtoColVersion, // value: u16 == 0x0303
    random: Random,
    legacy_session_id: [u8; 1], // value == [0]
    cipher_suites: CipherSuites,
    legacy_compression_methods: [u8; 2], // value == [1, 0]
    extensions: ClientExtensions,
}

#[allow(dead_code)]
impl ClientHelloMsg {
    pub fn size(&self) -> usize {
        1 + // 0: content_type
            2 + // 1: legacy_rec_version
            2 + // 3: fragment_len
            1 + // 5: handshake_type = client_hello == 1
            3 + // 6: message_len = (fragment_len - 4)
            2 + // 9: legacy_version
            32 + // 11: random
            1 + // 43: session_id_len = 0. In th implementation, value == 0
            2 + // 44: cipher_suite_len; uses 2 bytes (u16)
            // 46: list_of(cipher_suite) -- cipher_suite_len bytes
            2 * self.cipher_suites.count() +
            2 + // (46 + cipher_suite_len): compression_methods = (1, 0)
            2 + // (46 + cipher_suite_len + 2): ext_len
            // (46 + cipher_suite_len + 2 + 2): list_of(extension)
            self.extensions.size()
    }

    pub fn serialize(&self, bytes: &mut [u8]) -> Result<usize, Mutter> {
        if self.size() > bytes.len() {
            return Err(Mutter::SerializationBufferInsufficient);
        }
        // first five bytes of the message hold content_type, legacy_version, and fragment_len.
        let frag_len: u16 = self.size() as u16 - 5;
        bytes[0..3].copy_from_slice(&[
            22, // 0: content_type = handshake
            0x3, 0x03, // 1: legacy_record_version
        ]);
        // 3: fragment_len
        bytes[3..5].copy_from_slice(&frag_len.to_be_bytes());
        let mut i: usize = 5;
        // 5: handshake_type; client_hello == 1
        bytes[i] = 1;
        i += 1;
        // 6: message_len - 3 bytes.
        bytes[i] = 0;
        bytes[i + 1..i + 3].copy_from_slice(&(frag_len - 4).to_be_bytes());
        i += 3;
        // 9: legacy_version
        (bytes[i], bytes[i + 1]) = (3, 3);
        i += 2;
        // 11: random
        bytes[i..i + 32].copy_from_slice(self.random.as_slice());
        i += 32;
        // 43: session_id = (0) - essentially an empty session id.
        bytes[i] = 0;
        i += 1;
        // 46: (0, cipher_suite_len, ...)
        i += self.cipher_suites.serialize(&mut bytes[i..]);
        // 50: compression_methods = (1, 0)
        (bytes[i], bytes[i + 1]) = (1, 0);
        // 51: extensions_len (2 bytes)
        i += 2;
        let k = i;
        i += 2;
        // 53: extensions
        i += self.extensions.serialize(bytes, i);
        (bytes[k], bytes[k + 1]) = (0, (i - k - 2) as u8);
        assert_eq!(self.size(), i);
        Ok(self.size())
    }

    pub fn try_from(
        random: Random,
        ciphers: Vec<CipherSuiteId>,
        extensions: ClientExtensions,
    ) -> Result<Self, Mutter> {
        // self.size() shows that a client hello message needs 50+ bytes of data.
        // we subtract five bytes of the record header to reach the first byte of the handshake message.
        // That's how we arrive at the magic number 45 below.
        let ch_frag_len = 45 + ciphers.len() * 2 + extensions.size();

        if ch_frag_len >= (1 << 14) + 3 {
            return Err(Mutter::TooBig);
        }

        let res = Ok(ClientHelloMsg {
            rct: RecordContentType::Handshake,
            legacy_rec_ver: to_u16(0x03, 0x03),
            fragment_len: ch_frag_len as u16,
            ht: HandshakeType::ClientHello,
            // notice the message consumes 9 bytes, including the 'len' field which is 3-bytes long.
            // therefore, the data following this len field is 9 bytes less than the fragment length.
            len: (ch_frag_len - 9) as u32,
            // the following data occupies exactly 'len' bytes.
            legacy_tls_ver: to_u16(0x03, 0x03),
            random,
            legacy_session_id: [0],
            cipher_suites: CipherSuites::try_from(ciphers)?,
            legacy_compression_methods: [1, 0], // no legacy compression methods in TLS 1.3
            extensions,
        });

        res
    }

    pub fn key_shares(&self) -> &[ServerSessionPublicKey] {
        self.extensions.key_share_extensions().extensions()
    }
}
