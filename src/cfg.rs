use crate::def::{AlertDesc, CipherSuiteId, SignatureScheme, SupportedGroup};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PeerSessionConfig {
    pub(crate) id: String,
    pub(crate) tls_addr: String,
    pub(crate) path: String,
    pub(crate) dh_groups: Vec<SupportedGroup>,
    pub(crate) cipher_suites: Vec<CipherSuiteId>,
    pub(crate) sig_algs: Vec<SignatureScheme>,
    pub(crate) expect_good: bool,
    pub(crate) expect_alert: Option<AlertDesc>,
}

#[allow(dead_code)]
impl PeerSessionConfig {
    pub fn fail(
        name: &str,
        tls_addr: &str,
        path: &str,
        dh_groups: &[SupportedGroup],
        sig_algs: &[SignatureScheme],
        cipher_suites: &[CipherSuiteId],
        alert: AlertDesc,
    ) -> Self {
        PeerSessionConfig {
            id: name.to_owned(),
            tls_addr: tls_addr.to_owned(),
            path: path.to_owned(),
            dh_groups: dh_groups.into(),
            cipher_suites: cipher_suites.into(),
            sig_algs: sig_algs.into(),
            expect_good: false,
            expect_alert: Some(alert),
        }
    }

    pub fn good(
        name: &str,
        tls_addr: &str,
        path: &str,
        dh_groups: &[SupportedGroup],
        sig_algs: &[SignatureScheme],
        cipher_suites: &[CipherSuiteId],
    ) -> Self {
        PeerSessionConfig {
            id: name.to_owned(),
            tls_addr: tls_addr.to_owned(),
            path: path.to_owned(),
            dh_groups: dh_groups.into(),
            cipher_suites: cipher_suites.into(),
            sig_algs: sig_algs.into(),
            expect_good: true,
            expect_alert: None,
        }
    }

    pub fn ebay() -> Self {
        PeerSessionConfig::good(
            "www.ebay.com",
            "www.ebay.com:443",
            "",
            &[SupportedGroup::X25519, SupportedGroup::Secp256r1],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn ycombinator() -> Self {
        PeerSessionConfig::good(
            "ycombinator.com",
            "ycombinator.com:443",
            "",
            &[SupportedGroup::X25519, SupportedGroup::Secp256r1],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn your_dot_net() -> Self {
        PeerSessionConfig::good(
            "yourdot.net",
            "yourdot.net:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn microsoft() -> Self {
        PeerSessionConfig::good(
            "www.microsoft.com",
            "www.microsoft.com:443",
            "/en-in/",
            &[SupportedGroup::Secp256r1, SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn spacex() -> Self {
        PeerSessionConfig::good(
            "www.spacex.com",
            "www.spacex.com:443",
            "",
            &[SupportedGroup::Secp256r1, SupportedGroup::X25519],
            &[
                SignatureScheme::EcdsaSecp256r1Sha256,
                SignatureScheme::RsaPssRsaeSha256,
            ],
            &[CipherSuiteId::TlsAes256GcmSha384],
        )
    }

    pub fn google() -> Self {
        PeerSessionConfig::good(
            "www.google.com",
            "www.google.com:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsChacha20Poly1305Sha256],
        )
    }

    pub fn apple() -> Self {
        PeerSessionConfig::good(
            "www.apple.com",
            "www.apple.com:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsChacha20Poly1305Sha256],
        )
    }

    pub fn stack_exchange() -> Self {
        PeerSessionConfig::good(
            "stackexchange.com",
            "stackexchange.com:443",
            "about",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn github() -> Self {
        PeerSessionConfig::good(
            "github.com",
            "github.com:443",
            "/trending",
            &[SupportedGroup::X25519],
            &[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn x() -> Self {
        PeerSessionConfig::good(
            "x.com",
            "x.com:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn lets_encrypt() -> Self {
        PeerSessionConfig::good(
            "letsencrypt.org",
            "letsencrypt.org:443",
            "",
            &[SupportedGroup::X25519],
            &[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            &[CipherSuiteId::TlsAes256GcmSha384],
        )
    }

    pub fn india() -> Self {
        PeerSessionConfig::good(
            "www.india.gov.in",
            "www.india.gov.in:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsChacha20Poly1305Sha256],
        )
    }

    pub fn mozilla() -> Self {
        PeerSessionConfig::good(
            "www.mozilla.org",
            "www.mozilla.org:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn usa() -> Self {
        PeerSessionConfig::good(
            "www.usa.gov",
            "www.usa.gov:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn nsa() -> Self {
        PeerSessionConfig::good(
            "www.nsa.gov",
            "www.nsa.gov:443",
            "Cybersecurity/",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes256GcmSha384],
        )
    }

    pub fn mitre() -> Self {
        PeerSessionConfig::good(
            "www.mitre.org",
            "www.mitre.org:443",
            "",
            &[SupportedGroup::X25519, SupportedGroup::Secp256r1],
            &[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
                SignatureScheme::RsaPssRsaeSha256,
            ],
            &[
                CipherSuiteId::TlsAes256GcmSha384,
                CipherSuiteId::TlsChacha20Poly1305Sha256,
            ],
        )
    }

    pub fn lobsters() -> Self {
        PeerSessionConfig::good(
            "lobste.rs",
            "lobste.rs:443",
            "",
            &[SupportedGroup::X25519],
            &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn facebook() -> Self {
        PeerSessionConfig::good(
            "www.facebook.com",
            "www.facebook.com:443",
            "",
            &[SupportedGroup::X25519],
            &[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }

    pub fn whatsapp() -> Self {
        PeerSessionConfig::good(
            "www.whatsapp.com",
            "www.whatsapp.com:443",
            "",
            &[SupportedGroup::X25519],
            &[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            &[CipherSuiteId::TlsChacha20Poly1305Sha256],
        )
    }

    pub fn meta() -> Self {
        PeerSessionConfig::good(
            "www.meta.com",
            "www.meta.com:443",
            "",
            &[SupportedGroup::X25519],
            &[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            &[CipherSuiteId::TlsAes256GcmSha384],
        )
    }

    pub fn dicp() -> Self {
        PeerSessionConfig::good(
            "dicp.edu",
            "dicp.edu:443",
            "dicp.html",
            &[SupportedGroup::X25519],
            &[
                SignatureScheme::RsaPssRsaeSha256,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ],
            &[CipherSuiteId::TlsAes128GcmSha256],
        )
    }
}
