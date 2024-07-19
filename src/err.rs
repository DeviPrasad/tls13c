#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Debug)]
pub enum Mutter {
    RecType = 1,
    LegacyRecordVer = 2,
    FragmentLen = 4,
    LegacyTLS13MsgVer = 7,
    MsgLen = 10,
    RandomVal = 14,
    SessionIdLen = 19,
    CipherSuiteLen = 23,
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
    ExtensionData = 65,
    
    HmacBadKeyLen = 103,
    AEADKeyLenBad = 104,
    AEADNonceLenBad = 105,
    BadNonce = 106,

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

    BadInput = 255,
}