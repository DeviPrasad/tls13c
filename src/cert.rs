use crate::def::{HandshakeType, SignatureScheme};
use crate::deser::DeSer;
use crate::err::Mutter;
use rsa::pkcs1::der::referenced::OwnedToRef;
use rsa::signature::{SignatureEncoding, Verifier};
use rsa::RsaPublicKey;
use sha2::Sha256;
use std::time;
use std::time::UNIX_EPOCH;
use x509_cert::der::Decode;
use x509_cert::Certificate;

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
        // iterate over each RFC 7250 ASN.1_subjectPublicKeyInfo CertificateEntry
        let mut cert_list = Vec::<Certificate>::new();
        while cert_deser.available() > 0 {
            let cert_entry_size = cert_deser.ru24() as usize;
            let cert_entry_data = cert_deser.slice(cert_entry_size);
            log::info!("Certificate: cert size = {cert_entry_size}");
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
            cert_list.push(cert);
        }
        assert_eq!(cert_deser.cursor(), cert_list_len + 4);

        Ok((
            Self {
                cert_req_ctx: vec![],
                cert_list,
            },
            [head.as_slice(), server_cert_data].concat(),
        ))
    }

    pub fn certificate(&self) -> Option<Certificate> {
        self.cert_list.first().cloned()
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
                assert_eq!(sig.encoded_len(), 256);
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
