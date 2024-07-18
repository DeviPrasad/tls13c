use crate::def::{AlertDesc, SignatureScheme, SupportedGroup};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PeerSessionConfig {
    pub(crate) id: String,
    pub(crate) tls_addr: String,
    pub(crate) dh_groups: Vec<SupportedGroup>,
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
                alert: AlertDesc) -> Self {
        PeerSessionConfig {
            id: name.to_owned(),
            tls_addr: tls_addr.to_owned(),
            dh_groups: dh_groups.into(),
            sig_algs: sig_algs.into(),
            expect_good: false,
            expect_alert: Some(alert),
        }
    }

    pub fn good(name: &str,
                tls_addr: &str,
                dh_groups: &[SupportedGroup],
                sig_algs: &[SignatureScheme]) -> Self {
        PeerSessionConfig {
            id: name.to_owned(),
            tls_addr: tls_addr.to_owned(),
            dh_groups: dh_groups.into(),
            sig_algs: sig_algs.into(),
            expect_good: true,
            expect_alert: None,
        }
    }

    pub fn microsoft() -> Self {
        PeerSessionConfig::good("microsoft.com",
                                "microsoft.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha512])
    }

    pub fn spacex() -> Self {
        PeerSessionConfig::good("spacex.com",
                                "www.spacex.com:443",
                                &[SupportedGroup::Secp256r1],
                                &[SignatureScheme::EcdsaSecp256r1Sha256, SignatureScheme::RsaPssRsaeSha256])
    }

    pub fn google() -> Self {
        PeerSessionConfig::good("google.com",
                                "www.google.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256])
    }

    pub fn apple() -> Self {
        PeerSessionConfig::good("apple.com",
                                "apple.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256])
    }

    pub fn x() -> Self {
        PeerSessionConfig::good("x.com",
                                "x.com:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256])
    }

    pub fn lets_encrypt() -> Self {
        PeerSessionConfig::good("letsencrypt.org",
                                "letsencrypt.org:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256])
    }

    pub fn india() -> Self {
        PeerSessionConfig::good("india.gov",
                                "www.india.gov:443",
                                &[SupportedGroup::X25519],
                                &[SignatureScheme::Ed25519, SignatureScheme::RsaPssRsaeSha256])
    }
}