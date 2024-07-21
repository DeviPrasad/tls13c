use crate::def::{AlertDesc, CipherSuite, SignatureScheme, SupportedGroup};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PeerSessionConfig {
    pub(crate) id: String,
    pub(crate) tls_addr: String,
    pub(crate) dh_groups: Vec<SupportedGroup>,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) sig_algs: Vec<SignatureScheme>,
    pub(crate) expect_good: bool,
    pub(crate) expect_alert: Option<AlertDesc>
}

#[allow(dead_code)]
impl PeerSessionConfig {
    pub fn fail(name: &str,
                tls_addr: &str,
                dh_groups: &[SupportedGroup],
                sig_algs: &[SignatureScheme],
                cipher_suites: &[CipherSuite],
                alert: AlertDesc) -> Self {
        PeerSessionConfig {
            id: name.to_owned(),
            tls_addr: tls_addr.to_owned(),
            dh_groups: dh_groups.into(),
            cipher_suites: cipher_suites.into(),
            sig_algs: sig_algs.into(),
            expect_good: false,
            expect_alert: Some(alert),
        }
    }

    pub fn good(name: &str,
                tls_addr: &str,
                dh_groups: &[SupportedGroup],
                sig_algs: &[SignatureScheme],
                cipher_suites: &[CipherSuite]) -> Self {
        PeerSessionConfig {
            id: name.to_owned(),
            tls_addr: tls_addr.to_owned(),
            dh_groups: dh_groups.into(),
            cipher_suites: cipher_suites.into(),
            sig_algs: sig_algs.into(),
            expect_good: true,
            expect_alert: None,
        }
    }

    pub fn ebay() -> Self {
        PeerSessionConfig::good("ebay.com",
                                "ebay.com:443",
                                &[SupportedGroup::X25519, SupportedGroup::Secp256r1],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn your_dot_net() -> Self {
        PeerSessionConfig::good("yourdot.net",
                                "yourdot.net:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn microsoft() -> Self {
        PeerSessionConfig::good("microsoft.com",
                                "microsoft.com:443",
                                &[SupportedGroup::Secp256r1, SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn spacex() -> Self {
        PeerSessionConfig::good("spacex.com",
                                "www.spacex.com:443",
                                &[SupportedGroup::Secp256r1, SupportedGroup::X25519],
                                &[SignatureScheme::EcdsaSecp256r1Sha256, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn google() -> Self {
        PeerSessionConfig::good("google.com",
                                "www.google.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn apple() -> Self {
        PeerSessionConfig::good("apple.com",
                                "apple.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn stack_exchange() -> Self {
        PeerSessionConfig::good("stackexchange.com",
                                "stackexchange.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn github() -> Self {
        PeerSessionConfig::good("github.com",
                                "github.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::EcdsaSecp256r1Sha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn x() -> Self {
        PeerSessionConfig::good("x.com",
                                "x.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn lets_encrypt() -> Self {
        PeerSessionConfig::good("letsencrypt.org",
                                "letsencrypt.org:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::EcdsaSecp256r1Sha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn india() -> Self {
        PeerSessionConfig::good("india.gov",
                                "www.india.gov.in:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn mozilla() -> Self {
        PeerSessionConfig::good("mozilla.org",
                                "mozilla.org:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn usa() -> Self {
        PeerSessionConfig::good("usa.gov",
                                "usa.gov:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn nsa() -> Self {
        PeerSessionConfig::good("nsa.gov",
                                "nsa.gov:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn mitre() -> Self {
        PeerSessionConfig::good("mitre.org",
                                "www.mitre.org:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn lobsters() -> Self {
        PeerSessionConfig::good("lobste.rs",
                                "lobste.rs:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn facebook() -> Self {
        PeerSessionConfig::good("facebook.com",
                                "www.facebook.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::EcdsaSecp256r1Sha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn whatsapp() -> Self {
        PeerSessionConfig::good("whatsapp.com",
                                "www.whatsapp.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::EcdsaSecp256r1Sha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }

    pub fn meta() -> Self {
        PeerSessionConfig::good("meta.com",
                                "www.meta.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::EcdsaSecp256r1Sha256],
                                &[CipherSuite::TlsAes128GcmSha256])
    }
}