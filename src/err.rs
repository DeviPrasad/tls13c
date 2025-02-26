#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Debug)]
pub enum Error {
    RecType = 1,
    LegacyRecordVer = 2,
    FragmentLen = 4,
    BadVarLenVec = 5,
    LegacyTLS13MsgVer = 7,
    MsgLen = 10,
    RandomVal = 14,
    SessionIdLen = 19,
    UnexpectedSessionIdInServerHello = 20,
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
    UnsupportedSignatureSchemeInCertificateVerify = 55,
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
    BadRsaPssRsaeSha256Signature = 630,
    BadEcdsaP256Signature = 633,
    BadSubjectPublicKeyInfo = 635,
    BadCertificateSignatureLen = 638,
    CertificateSignatureVerificationFailed = 640,
    MissingCertificateSignature = 643,
    InvalidCertificateRequestContext = 644,
    TooManyCertificateListEntries = 645,
    BadX509Certificate = 646,
    PostDatedCertificate = 647,
    ExpiredCertificate = 648,
    InvalidSystemRootCACert = 649,
    EmptySystemRootCACerts = 650,
    MissingCARootCertificate = 651,
    CertificateWithCommonNameNotFound = 652,
    UnsupportedSigSchemeInCertChainValidation = 653,
    UnsupportedECDSASchemeInCertChainValidation = 654,
    UnsupportedDSASchemeInCertChainValidation = 655,

    AlertCloseNotify = 680,
    AlertHandshakeFailure = 681,
    AlertIllegalParameter = 682,
    AlertMissingExtension = 683,
    AlertUnsupportedExtension = 684,
    AlertUnrecognizedName = 685,
    AlertGeneric = 686,

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
    ServerSocketConnectFailed = 174,
    ProbablyEmptyStream = 175,

    TooBig = 221,
    MsgSizeInvalid = 222,
    NotImpl = 224,

    RandomGen = 238,
    MissingX25519Key = 240,
    Secp256r1NotYetSupported = 244,
    X25519KeyLenBad = 247,
    Secp256r1KeyLenBad = 248,
    ServerKeyShareBad = 249,
    EmptyDHSecret = 250,

    BadInput = 255,

    InternalError = 512,
}

impl<T> Into<Result<T, Error>> for Error {
    fn into(self) -> Result<T, Error> {
        Err(self)
    }
}
