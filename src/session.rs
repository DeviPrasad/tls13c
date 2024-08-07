use crate::cfg::PeerSessionConfig;
use crate::err::Mutter;
use crate::sock::TlsStream;

#[allow(dead_code)]
#[derive(Debug)]
pub struct TlsConnection {
    pub(crate) peer: PeerSessionConfig,
    // pub(crate) stream: Transport,
    pub(crate) stream: TlsStream,
}

#[allow(dead_code)]
pub struct HandshakeSession {
    pub(crate) peer: PeerSessionConfig,
    // pub(crate) stream: Transport,
    pub(crate) stream: TlsStream,
    msg_ctx: Vec<u8>,
    transcript_hash: Vec<u8>,
}

#[allow(dead_code)]
pub struct AuthnSession {
    pub(crate) peer: PeerSessionConfig,
    pub(crate) stream: TlsStream,
    msg_ctx: Vec<u8>,
    transcript_hash: Vec<u8>,
    dh_secret: [u8; 32],
}

#[allow(dead_code)]
impl TlsConnection {
    pub fn with_peer(peer: &PeerSessionConfig) -> Result<Self, Mutter> {
        let stream = TlsStream::new(&peer.tls_addr)?;
        Ok(Self {
            peer: peer.clone(),
            stream,
        })
    }
}
