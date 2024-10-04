use crate::def::{HandshakeType, SignatureScheme};
use crate::deser::DeSer;
use crate::err::Mutter;
use rsa::pkcs1::der::referenced::OwnedToRef;
use rsa::signature::digest::Digest;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384};
use std::collections::HashMap;
use std::time;
use std::time::UNIX_EPOCH;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

#[allow(unused)]
pub struct CACertMap {
    root: HashMap<String, Certificate>,
}

impl CACertMap {
    pub fn common_name(cert: &Certificate) -> Result<String, Mutter> {
        Self::common_name_from_str(cert.tbs_certificate.subject.to_string())
    }

    pub fn common_name_from_str(s: String) -> Result<String, Mutter> {
        let ss: Vec<&str> = s.split(',').collect();
        ss.iter()
            .find(|&&s| s.starts_with("CN=") || s.starts_with("OU="))
            .map(|name| name[3..].to_string())
            .ok_or(Mutter::BadX509Certificate)
    }
}
impl CACertMap {
    pub fn try_init() -> Result<Self, Mutter> {
        let cl = rustls_native_certs::load_native_certs();
        if !cl.errors.is_empty() || cl.certs.is_empty() {
            log::error!("load_native_certs failed to find CA certificates");
            return Mutter::EmptySystemRootCACerts.into();
        }
        let mut root = HashMap::<String, Certificate>::new();
        for cert_der in cl.certs.iter() {
            let cert = Certificate::from_der(cert_der).map_err(|_e| {
                log::error!("load_native_certs failed to find CA certificates: {_e:#?}");
                Mutter::InvalidSystemRootCACert
            })?;
            Self::common_name(&cert).map(|name| root.insert(name, cert))?;
        }
        Ok(Self { root })
    }

    pub fn have_cert(&self, cn: String) -> Result<&Certificate, Mutter> {
        if let Some(cert) = self.root.get(&cn) {
            Ok(cert)
        } else {
            Mutter::CertificateWithCommonNameNotFound.into()
        }
    }
}

// section 4.4.2, Certificate, page 64.
#[allow(unused)]
#[repr(u8)]
#[derive(Clone, Debug)]
pub enum CertificateType {
    X509 = 0,
    RawPublicKey = 2,
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct CertificateMsg {
    // cert_req_ctx.len() == 0 in the case of server authentication.
    // 0 < cert_req_ctx.len() < 2**8 when CertificateMsg is in response to a CertificateRequest.
    cert_req_ctx: Vec<u8>,
    cert_list: Vec<Certificate>,
}

impl CertificateMsg {
    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, Vec<u8>), Mutter> {
        log::info!("Server Certificate Chain");
        if !deser.have(4) {
            return Mutter::DeserializationBufferInsufficient.into();
        }
        if deser.peek_u8() != HandshakeType::Certificate as u8 {
            return Mutter::ExpectingCertificateVerifyMsg.into();
        };
        let len = deser.peek_u24_at(1) as usize;
        if !deser.have(4 + len) {
            return Mutter::DeserializationBufferInsufficient.into();
        }

        let head: [u8; 4] = deser
            .slice(4)
            .try_into()
            .map_err(|_| Mutter::InternalError)?;

        let server_cert_data = deser.slice(len);

        let mut cert_deser = DeSer::new(server_cert_data);
        // certificate request context must be zero length
        let serv_cert_req_ctx = cert_deser.ru8() as usize;
        if serv_cert_req_ctx != 0 {
            return Mutter::InvalidCertificateRequestContext.into();
        }
        let cert_list_len = cert_deser.ru24() as usize;
        assert_eq!(cert_list_len + 4, len);
        if cert_list_len == 0 || cert_list_len > ((1 << 24) - 1) {
            return Mutter::TooManyCertificateListEntries.into();
        }
        // X.509 certificates
        let mut tls_serv_cert_list = Vec::<Certificate>::new();
        while cert_deser.available() > 0 {
            let cert_entry_size = cert_deser.ru24() as usize;
            let cert_entry_data = cert_deser.slice(cert_entry_size);
            // log::info!("Certificate: cert size = {cert_entry_size}");
            let cert_extensions = cert_deser.ru16();
            assert_eq!(cert_extensions, 0);
            let cert = Certificate::from_der(cert_entry_data).map_err(|e| {
                log::error!("ServerCertificate Error - {e:#?}");
                Mutter::BadX509Certificate
            })?;
            let name = cert.tbs_certificate.subject.to_string();
            if let Some(i) = name.find("CN=") {
                if let Some(j) = &name[i..name.len()].find(',') {
                    log::info!("\tCN: {:?}", &name[i + 3..i + *j]);
                } else {
                    log::info!("\tCN: {:?}", &name[i + 3..]);
                }
            }
            let issuer = cert.tbs_certificate.issuer.to_string();
            log::info!("\tissuer CN: {:?}", issuer);
            // check the timestamps in the certificate.
            // reject if it is too early (premature) or too late (expired) to use the certificate.
            if time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                < cert.tbs_certificate.validity.not_before.to_unix_duration()
            {
                return Mutter::PostDatedCertificate.into();
            }
            if time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                > cert.tbs_certificate.validity.not_after.to_unix_duration()
            {
                return Mutter::ExpiredCertificate.into();
            }
            // store it for later use in VerifySignature
            tls_serv_cert_list.push(cert);
        }
        assert_eq!(cert_deser.cursor(), cert_list_len + 4);

        let sys_ca_certs = CACertMap::try_init()?;
        if let Some(tls_serv_cert_list_root) = tls_serv_cert_list.last() {
            match CACertMap::common_name(tls_serv_cert_list_root) {
                Ok(root_cn) => {
                    if let Ok(root_ca_cert) = sys_ca_certs.have_cert(root_cn) {
                        assert_eq!(
                            tls_serv_cert_list_root
                                .tbs_certificate
                                .subject_public_key_info,
                            root_ca_cert.tbs_certificate.subject_public_key_info
                        );
                        assert_eq!(
                            tls_serv_cert_list_root.tbs_certificate.subject_unique_id,
                            root_ca_cert.tbs_certificate.subject_unique_id
                        );
                        assert_eq!(
                            tls_serv_cert_list_root.tbs_certificate.subject,
                            root_ca_cert.tbs_certificate.subject
                        );
                        assert!(
                            tls_serv_cert_list_root
                                .tbs_certificate
                                .validity
                                .not_before
                                .to_unix_duration()
                                >= root_ca_cert
                                    .tbs_certificate
                                    .validity
                                    .not_before
                                    .to_unix_duration()
                        );
                        assert!(
                            tls_serv_cert_list_root
                                .tbs_certificate
                                .validity
                                .not_after
                                .to_unix_duration()
                                <= root_ca_cert
                                    .tbs_certificate
                                    .validity
                                    .not_after
                                    .to_unix_duration()
                        );
                    } else if let Ok(issuer_cn) = CACertMap::common_name_from_str(
                        tls_serv_cert_list_root.tbs_certificate.issuer.to_string(),
                    ) {
                        let issuer_ca_cert = sys_ca_certs.have_cert(issuer_cn)?;
                        tls_serv_cert_list.push(issuer_ca_cert.clone())
                    } else {
                        return Mutter::MissingCARootCertificate.into();
                    }
                }
                _ => return Mutter::MissingCARootCertificate.into(),
            }

            Self::verify_chain(&tls_serv_cert_list)?;

            return Ok((
                Self {
                    cert_req_ctx: vec![],
                    cert_list: tls_serv_cert_list,
                },
                [head.as_slice(), server_cert_data].concat(),
            ));
        }
        Mutter::InvalidSystemRootCACert.into()
    }

    pub fn certificate(&self) -> Option<Certificate> {
        self.cert_list.first().cloned()
    }

    // RSA with PKCS#1 v1.5 padding for the specified digest.
    fn verify_rsa_signature(
        target_cert: &Certificate,
        issuer_cert: &Certificate,
    ) -> Result<(), Mutter> {
        let target_cert_der = &target_cert.tbs_certificate.to_der().unwrap();
        let target_cert_sig = target_cert.signature.raw_bytes();
        let issuer_spki = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();

        if "1.2.840.113549.1.1.11" == target_cert.signature_algorithm.oid.to_string() {
            // sha256WithRSAEncryption
            let rsa_pub_key =
                RsaPublicKey::try_from(issuer_spki).map_err(|_| Mutter::BadSubjectPublicKeyInfo)?;
            let mut sha256 = Sha256::new();
            sha256.update(target_cert_der);
            let cert_hash = sha256.finalize();
            rsa_pub_key
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(),
                    &cert_hash,
                    target_cert_sig,
                )
                .map_err(|_| Mutter::CertificateSignatureVerificationFailed)
        } else if "1.2.840.113549.1.1.12" == target_cert.signature_algorithm.oid.to_string() {
            // sha384WithRSAEncryption
            let rsa_pub_key =
                RsaPublicKey::try_from(issuer_spki).map_err(|_| Mutter::BadSubjectPublicKeyInfo)?;
            let mut sha384 = Sha384::new();
            sha384.update(target_cert_der);
            let cert_hash = sha384.finalize();
            // create new PKCS#1 v1.5 padding for the given digest.
            rsa_pub_key
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha384>(),
                    &cert_hash,
                    target_cert_sig,
                )
                .map_err(|_| Mutter::CertificateSignatureVerificationFailed)
        } else {
            Err(Mutter::UnsupportedDSASchemeInCertChainValidation)
        }?;
        Ok(())
    }

    fn verify_ecdsa_signature(
        target_cert: &Certificate,
        issuer_cert: &Certificate,
    ) -> Result<(), Mutter> {
        let target_cert_der = &target_cert.tbs_certificate.to_der().unwrap();
        let target_cert_sig = target_cert.signature.raw_bytes();
        let issuer_spki = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();

        if "1.2.840.10045.4.3.2" == target_cert.signature_algorithm.oid.to_string() {
            // ecdsa with sha256
            let sig = p256::ecdsa::DerSignature::try_from(target_cert_sig)
                .map_err(|_| Mutter::BadEcdsaP256Signature)?;
            let vk = p256::ecdsa::VerifyingKey::try_from(issuer_spki)
                .map_err(|_| Mutter::BadSubjectPublicKeyInfo)?;
            vk.verify(target_cert_der, &sig)
                .map_err(|_| Mutter::CertificateSignatureVerificationFailed)
        } else if "1.2.840.10045.4.3.3" == target_cert.signature_algorithm.oid.to_string() {
            // ecdsa with sha384
            let sig = p384::ecdsa::DerSignature::try_from(target_cert_sig)
                .map_err(|_| Mutter::BadEcdsaP256Signature)?;
            let vk = p384::ecdsa::VerifyingKey::try_from(issuer_spki)
                .map_err(|_| Mutter::BadSubjectPublicKeyInfo)?;
            vk.verify(target_cert_der, &sig)
                .map_err(|_| Mutter::CertificateSignatureVerificationFailed)
        } else {
            Err(Mutter::UnsupportedECDSASchemeInCertChainValidation)
        }?;
        Ok(())
    }

    // Most certificates bear signatures produced by SHA256-with-RSA-Encryption.
    // Github uses ECDSA, though.
    fn verify_chain(certs: &[Certificate]) -> Result<(), Mutter> {
        for i in 0..certs.len() - 1 {
            let target_cert = certs.get(i).unwrap().clone();
            let issuer_cert = certs.get(i + 1).unwrap().clone();
            let sig_alg_oid = target_cert.signature_algorithm.oid.to_string();

            if sig_alg_oid == "1.2.840.113549.1.1.11" || sig_alg_oid == "1.2.840.113549.1.1.12" {
                Self::verify_rsa_signature(&target_cert, &issuer_cert)
            } else if sig_alg_oid == "1.2.840.10045.4.3.2" || sig_alg_oid == "1.2.840.10045.4.3.3" {
                Self::verify_ecdsa_signature(&target_cert, &issuer_cert)
            } else {
                log::info!("Certificate Chain - unknown signature scheme");
                Mutter::UnsupportedSigSchemeInCertChainValidation.into()
            }?
        }
        log::info!("Certificate Chain validated");
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CertificateVerifyMsg {
    sig_scheme: SignatureScheme,
    signature: Vec<u8>,
}

impl CertificateVerifyMsg {
    pub fn deserialize(deser: &mut DeSer) -> Result<(Self, Vec<u8>), Mutter> {
        if !deser.have(4) {
            return Mutter::DeserializationBufferInsufficient.into();
        }
        if deser.peek_u8() != HandshakeType::CertificateVerify as u8 {
            return Mutter::ExpectingCertificateVerifyMsg.into();
        };
        let len = deser.peek_u24_at(1) as usize;

        if !deser.have(4 + len) {
            return Mutter::DeserializationBufferInsufficient.into();
        }
        let head: [u8; 4] = deser
            .slice(4)
            .try_into()
            .map_err(|_| Mutter::InternalError)?;

        let sig_scheme = SignatureScheme::try_from(deser.ru16())?;
        let sig_len = deser.peek_u16() as usize;
        assert_eq!(sig_len, len - 4);
        if sig_len > (1 << 16) - 1 {
            return Mutter::BadCertificateSignatureLen.into();
        }
        let sig = deser.slice(len - 2);
        if sig.is_empty() {
            Mutter::MissingCertificateSignature.into()
        } else {
            Ok((
                Self {
                    // head,
                    sig_scheme,
                    signature: sig[2..].into(), // leave the size bytes; retain only the signature
                },
                [head.as_slice(), &(sig_scheme as u16).to_be_bytes(), sig].concat(),
            ))
        }
    }

    pub fn supported_sig_scheme(&self, sig_algs: &[SignatureScheme]) -> bool {
        sig_algs.contains(&self.sig_scheme)
    }

    // RFC 8446, Pages 69-70.
    // Section 4.4.1. Certificate Verify
    // The
    fn server_signed_content(data: &[u8]) -> Vec<u8> {
        let mut content = vec![32u8; 64];
        content.extend_from_slice("TLS 1.3, server CertificateVerify".as_bytes());
        content.push(0u8);
        content.extend(data);

        content
    }

    // RFC 8446, Page 62.
    // A signature over the value Transcript-Hash(Handshake Context, Certificate).
    // Inspiration: https://github.com/RustCrypto/formats/issues/838#event-13922627104
    pub fn verify(&self, transcript_hash: Vec<u8>, cert: Certificate) -> Result<(), Mutter> {
        let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();

        match self.sig_scheme {
            SignatureScheme::RsaPssRsaeSha256 => {
                let sig: rsa::pss::Signature = self
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| Mutter::BadRsaPssRsaeSha256Signature)?;
                // watch the two steps in obtaining the signature verification key
                let rsa_pub_key =
                    RsaPublicKey::try_from(spki).map_err(|_| Mutter::BadSubjectPublicKeyInfo)?;
                let vk = rsa::pss::VerifyingKey::<Sha256>::new(rsa_pub_key);
                vk.verify(&Self::server_signed_content(&transcript_hash), &sig)
                    .map_err(|_| Mutter::CertificateSignatureVerificationFailed)
            }
            SignatureScheme::EcdsaSecp256r1Sha256 => {
                let sig = p256::ecdsa::DerSignature::try_from(self.signature.as_slice())
                    .map_err(|_| Mutter::BadEcdsaP256Signature)?;
                // get the verification key in one step
                let vk = p256::ecdsa::VerifyingKey::try_from(spki)
                    .map_err(|_| Mutter::BadSubjectPublicKeyInfo)?;
                vk.verify(&Self::server_signed_content(&transcript_hash), &sig)
                    .map_err(|_| Mutter::CertificateSignatureVerificationFailed)
            }
            _ => {
                log::error!(
                    "Unsupported Signature Verification Scheme: {:#?}",
                    self.sig_scheme
                );
                Mutter::UnsupportedSignatureSchemeInCertificateVerify.into()
            }
        }
    }
}
