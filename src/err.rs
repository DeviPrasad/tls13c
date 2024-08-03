#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Debug)]
pub enum Mutter {
    RecType = 1,
    LegacyRecordVer = 2,
    FragmentLen = 4,
    BadVarLenVec = 5,
    LegacyTLS13MsgVer = 7,
    MsgLen = 10,
    RandomVal = 14,
    SessionIdLen = 19,
    CipherSuiteLen = 23,
    UnsupportedCipherSuite = 24,
    CipherUnsupported = 28,
    CipherDuplicate = 31,
    CipherBad = 37,
    CompressionMethods = 41,
    ExtensionLen = 44,
    ExtensionType = 47,
    UnsupportedExtension = 48,
    UnsupportedVersion = 50,
    UnsupportedHandshakeMessageType = 53,
    UnsupportedGroup = 54,
    UnsupportedSignatureScheme = 56,
    SignatureSchemeDuplicate = 57,
    DuplicateSupportedGroup = 58,
    SupportedGroupLen = 59,
    InvalidExtensionData = 65,

    InvalidRecordContentType = 81,
    SerializationBufferInsufficient = 82,
    DeserializationBufferInsufficient = 83,
    UnexpectedExtension = 84,
    ExpectingEncryptedExtensions = 85,

    ExpectingServerHello = 600,
    ExpectingChangeCipherSpec = 601,
    FinishMsgVerificationFailed = 604,
    ExpectingCertificateVerifyMsg = 606,
    ExpectingCiphertextRecord = 609,
    // ExpectingCiphertextAppData = 609,
    ExpectingFinishedMsg = 615,
    MissingCertificateSignature = 643,
    InvalidCertificateRequestContext = 644,
    TooManyCertificateListEntries = 645,

    NotTls13Record = 91,
    NotHandshakeMessage = 93,

    MissingInnerPlaintextContentType = 201,

    HmacBadKeyLen = 103,
    AEADKeyLenBad = 104,
    AEADNonceLenBad = 105,
    BadIV = 106,

    DecryptionFailed = 112,

    HandshakeType = 129,
    UnknownAlertDesc = 140,
    InvalidCipherSpecChange = 145,

    BadNetworkAddress = 165,
    TlsConnection = 166,
    StreamShutdownError = 167,
    StreamError = 168,
    StreamReadError = 169,
    StreamWriteError = 170,
    StreamReadinessError = 171,
    SocketPropertyError = 172,
    StreamTimeout = 173,

    TooBig = 221,
    MsgSizeInvalid = 222,
    NotImpl = 224,

    RandomGen = 238,
    MissingX25519Key = 240,
    Secp256r1NotYetSupported = 244,
    X25519KeyLenBad = 247,
    Secp256r1KeyLenBad = 248,
    ServerKeyShareBad = 249,

    BadInput = 255,

    InternalError = 1024,
}

impl<T> Into<Result<T, Mutter>> for Mutter {
    fn into(self) -> Result<T, Mutter> {
        Err(self)
    }
}
