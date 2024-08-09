use crate::def::{HandshakeType, SignatureScheme};
use crate::deser::DeSer;
use crate::err::Mutter;

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
pub struct CertificateEntry {
    cert_type: CertificateType,
    // 0 < cert_data.len() < 2**24
    cert_data: Vec<u8>,
    // 0 <= cert_data.len() < 2**16
    extensions: Vec<u8>,
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct CertificateMsg {
    head: [u8; 4],
    // cert_req_ctx.len() == 0 in the case of server authentication.
    // 0 < cert_req_ctx.len() < 2**8 when CertificateMsg is in response to a CertificateRequest.
    cert_req_ctx: Vec<u8>,
    cert_list: Vec<CertificateEntry>,
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

        // certificate request context must be zero length
        let cert_req_ctx = deser.peek_u8() as usize;
        if cert_req_ctx != 0 {
            return Mutter::InvalidCertificateRequestContext.into();
        }
        let cert_list_len = deser.peek_u24_at(1) as usize;
        if cert_list_len == 0 || cert_list_len > ((1 << 24) - 1) {
            return Mutter::TooManyCertificateListEntries.into();
        }

        let data = deser.slice(len);
        Ok((
            Self {
                head,
                cert_req_ctx: vec![],
                cert_list: vec![],
            },
            [head.as_slice(), data].concat(),
        ))
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CertificateVerifyMsg {
    head: [u8; 4],
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
        let sig = deser.slice(len - 2);
        if sig.is_empty() {
            Mutter::MissingCertificateSignature.into()
        } else {
            Ok((
                Self {
                    head,
                    sig_scheme: sig_scheme.into(),
                    signature: sig.into(),
                },
                [head.as_slice(), &(sig_scheme as u16).to_be_bytes(), &sig].concat(),
            ))
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        [
            self.head.as_slice(),
            (self.sig_scheme as u16).to_be_bytes().as_slice(),
            self.signature.as_slice(),
        ]
        .concat()
    }
}
