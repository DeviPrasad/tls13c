use crate::err::Mutter;

pub type ProtoColVersion = u16;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum LegacyRecordVersion {
    #[default]
    TlsLegacyVersion03003 = 0x0303
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum LegacyTlsVersion {
    #[default]
    TlsLegacyVersion03003 = 0x0303
}

pub type Random = [u8; 32];

#[allow(dead_code)]
// B.4. Cipher Suites. Use AES and/or CHACHA20,.
// TlsAes128GcmSha256 (0x13, 0x01)
// TlsAes256GcmSha384 (0x13, 0x02)
// TLS_CHACHA20_POLY1305_SHA256 (0x13, 0x03)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
    TlsAes128CcmSha256,
    TlsAes128Ccm8Sha256,
}

impl TryFrom<u16> for CipherSuite {
    type Error = Mutter;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::try_from(u16_to_u8_pair(val))
    }
}

impl TryFrom<(u8, u8)> for CipherSuite {
    type Error = Mutter;

    fn try_from(value: (u8, u8)) -> Result<Self, Self::Error> {
        match value {
            (0x13, 0x01) => Ok(CipherSuite::TlsAes128GcmSha256),
            (0x13, 0x02) => Ok(CipherSuite::TlsAes256GcmSha384),
            (0x13, 0x03) => Ok(CipherSuite::TlsChacha20Poly1305Sha256),
            (0x13, 0x04) => Ok(CipherSuite::TlsAes128CcmSha256),
            (0x13, 0x05) => Ok(CipherSuite::TlsAes128Ccm8Sha256),
            _ => Err(Mutter::CipherUnsupported)
        }
    }
}

#[allow(dead_code)]
pub type CipherSuiteCode = (u8, u8);

#[allow(dead_code)]
impl CipherSuite {
    pub fn code(&self) -> CipherSuiteCode {
        match self {
            CipherSuite::TlsAes128GcmSha256 => (0x13, 0x01),
            CipherSuite::TlsAes256GcmSha384 => (0x13, 0x02),
            CipherSuite::TlsChacha20Poly1305Sha256 => (0x13, 0x03),
            CipherSuite::TlsAes128CcmSha256 => (0x13, 0x04),
            CipherSuite::TlsAes128Ccm8Sha256 => (0x13, 0x05),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CipherSuites(Vec<CipherSuite>);

#[allow(dead_code)]
impl TryFrom<Vec<CipherSuite>> for CipherSuites {
    type Error = Mutter;

    fn try_from(cipher_suites: Vec<CipherSuite>) -> Result<Self, Mutter> {
        if !cipher_suites.is_empty() {
            let mut cipher_suite_dup: Vec<bool> = vec![true, false, false, false, false, false];
            for cs in cipher_suites.iter() {
                let (_, cl) = cs.code();
                if cipher_suite_dup[cl as usize] {
                    return Err(Mutter::CipherDuplicate)
                } else {
                    cipher_suite_dup[cl as usize] = true;
                }
            }
            Ok(CipherSuites(cipher_suites))
        } else {
            Err(Mutter::CipherSuiteLen)
        }
    }
}

#[allow(dead_code)]
impl CipherSuites {
    pub fn deserialize(bytes: &[u8]) -> Result<(CipherSuites, usize), Mutter> {
        let mut i: usize = 0;
        // cipher suites - len followed by identifiers; sequence of byte-pairs.
        let cipher_suite_len: usize = ((bytes[i] as usize) << 8) | bytes[i + 1] as usize;
        if (cipher_suite_len & 1 == 1) || !(2..=10).contains(&cipher_suite_len) {
            return Err(Mutter::CipherSuiteLen)
        }
        i += 2;
        let mut cipher_suites: Vec<CipherSuite> = vec![];
        let mut cipher_suite_dup = [true, false, false, false, false, false];
        for k in (0..cipher_suite_len).step_by(2) {
            let cm = bytes[i + k];
            let cl = bytes[i + 1 + k];
            let cs = CipherSuite::try_from((cm, cl))?;
            log::info!("\tcipher_suite: {cs:#?}");
            if cipher_suite_dup[cl as usize] {
                return Err(Mutter::CipherDuplicate)
            } else {
                cipher_suite_dup[cl as usize] = true;
                cipher_suites.push(cs);
            }
        }
        log::info!("\tdeserialized cipher_suites: {cipher_suites:#?}");
        Ok((CipherSuites(cipher_suites), cipher_suite_len + 2))
    }

    pub fn serialize(&self, bytes: &mut [u8]) -> usize {
        let cs_len = (self.0.len() * 2) as u16;
        let mut i = 0;
        bytes[i..i + 2].copy_from_slice(&cs_len.to_be_bytes());
        i += 2;
        for cs in self.0.iter() {
            (bytes[i], bytes[i + 1]) = cs.code();
            i += 2;
        }
        i
    }

    pub fn count(&self) -> usize {
        self.0.len()
    }
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RecordContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for RecordContentType {
    type Error = Mutter;

    fn try_from(val: u8) -> Result<Self, Mutter> {
        Ok(match val {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => return Err(Mutter::InvalidRecordContentType),
        })
    }
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
    #[default]
    Invalid = 255
}

impl From<u8> for HandshakeType {
    fn from(val: u8) -> Self {
        match val {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            13 => HandshakeType::CertificateRequest,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            _ => HandshakeType::Invalid,
        }
    }
}

#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExtensionTypeCode {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    ECPointFormats = 11,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    EncryptThenMAC = 22,
    ExtendedMasterSecret = 23,
    SessionTicket = 35,
    PreSharedKeys = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    Unused = 65535
}

impl Into<u16> for ExtensionTypeCode {
    fn into(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for ExtensionTypeCode {
    type Error = Mutter;

    fn try_from(val: u16) -> Result<Self, Mutter> {
        Self::try_from(u16_to_u8_pair(val))
    }
}

impl TryFrom<(u8, u8)> for ExtensionTypeCode {
    type Error = Mutter;

    fn try_from((u, v): (u8, u8)) -> Result<Self, Mutter> {
        match (u, v) {
            (0, 0) => Ok(Self::ServerName),
            (0, 10) => Ok(Self::SupportedGroups),
            (0, 11) => Ok(Self::ECPointFormats),
            (0, 13) => Ok(Self::SignatureAlgorithms),
            (0, 16) => Ok(Self::ApplicationLayerProtocolNegotiation),
            (0, 17) => Ok(Self::ExtendedMasterSecret),
            (0, 19) => Ok(Self::ClientCertificateType),
            (0, 20) => Ok(Self::ServerCertificateType),
            (0, 22) => Ok(Self::EncryptThenMAC),
            (0, 23) => Ok(Self::ExtendedMasterSecret),
            (0, 35) => Ok(Self::SessionTicket),
            (0, 43) => Ok(Self::SupportedVersions),
            (0, 45) => Ok(Self::PskKeyExchangeModes),
            (0, 51) => Ok(Self::KeyShare),
            _ => {
                log::error!("ExtensionType - error. Unsupported type ({},{})", u, v);
                Err(Mutter::UnsupportedExtension)
            }
        }
    }
}

// B.3.1.4. Supported Groups Extension. page 130.
#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SupportedGroup {
    Reserved = 0,
    /* elliptic curve groups */
    Secp256r1 = 0x0017,
    // Secp384r1 = 0x0018,
    // Secp512r1 = 0x0019,
    X25519 = 0x001D,
    // X448 = 0x001E,
    /* finite-field groups */
    // FFDHE2048 = 0x0100,
    // FFDHE3072 = 0x0101,
    // FFDHE4096 = 0x0102,
    // FFDHE6144 = 0x0103,
    // FFDHE8192 = 0x0104,

    Unused = 0xFFFF,
}

impl Into<u16> for SupportedGroup {
    fn into(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for SupportedGroup {
    type Error = Mutter;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0017 => Ok(Self::Secp256r1),
            0x001D => Ok(Self::X25519),
            _ => Err(Mutter::UnsupportedGroup)
        }
    }
}

impl SupportedGroup {
    pub fn key_size(&self) -> usize {
        match *self {
            Self::Secp256r1 | Self::X25519 => 32,
            _ => 0
        }
    }
    pub fn sln(&self) -> usize {
        match *self {
            Self::Secp256r1 => 1,
            Self::X25519 => 2,
            _ => 0
        }
    }
}

#[allow(dead_code)]
// section B.3.1.3. Signature Algorithm Extension, page 129
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SignatureScheme {
    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    /* EdDSA algorithms */
    Ed25519 = 0x0807,
    Ed448 = 0x0808,
}

impl TryFrom<u16> for SignatureScheme {
    type Error = Mutter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0403 => SignatureScheme::EcdsaSecp256r1Sha256,
            0x0804 => SignatureScheme::RsaPssRsaeSha256,
            0x0807 => SignatureScheme::Ed25519,
            _ => return Err(Mutter::UnsupportedSignatureScheme)
        })
    }
}

impl SignatureScheme {
    pub fn sln(&self) -> usize {
        match self {
            Self::EcdsaSecp256r1Sha256 => 1,
            Self::RsaPssRsaeSha256 => 2,
            Self::Ed25519 => 3,
            _ => usize::MAX,
        }
    }
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Debug, PartialEq)]
pub enum AlertDesc {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    CertificateRequired = 116,
    Bad = 255,
}

impl TryFrom<u8> for AlertDesc {
    type Error = Mutter;

    fn try_from(desc: u8) -> Result<Self, Self::Error> {
        match desc {
            0 => Ok(AlertDesc::CloseNotify),
            22 => Ok(AlertDesc::RecordOverflow),
            40 => Ok(AlertDesc::HandshakeFailure),
            50 => Ok(AlertDesc::DecodeError),
            70 => Ok(AlertDesc::ProtocolVersion),
            71 => Ok(AlertDesc::InsufficientSecurity),
            80 => Ok(AlertDesc::InternalError),
            109 => Ok(AlertDesc::MissingExtension),
            110 => Ok(AlertDesc::UnsupportedExtension),
            _ => Err(Mutter::UnknownAlertDesc),
        }
    }
}

pub fn to_u16(h: u8, l: u8) -> u16 {
    (h as u16) << 8 | l as u16
}

pub fn u16_to_u8_pair(v: u16) -> (u8, u8) {
    v.to_be_bytes().into()
}

pub fn u24_to_u8_triple(v: u32) -> (u8, u8, u8) {
    let bytes = v.to_be_bytes();
    assert_eq!(bytes.len(), 4);
    assert_eq!(bytes[0], 0);
    (bytes[1], bytes[2], bytes[3])
}


