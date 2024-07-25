use crate::cfg::PeerSessionConfig;
use crate::err::Mutter;
use crate::sock::Tls13Stream;

#[allow(dead_code)]
#[derive(Debug)]
pub struct EarlySession {
    pub(crate) peer: PeerSessionConfig,
    // pub(crate) stream: Transport,
    pub(crate) stream: Tls13Stream,
}

#[allow(dead_code)]
pub struct HandshakeSession {
    pub(crate) peer: PeerSessionConfig,
    // pub(crate) stream: Transport,
    pub(crate) stream: Tls13Stream,
    msg_ctx: Vec<u8>,
    transcript_hash: Vec<u8>,
}

#[allow(dead_code)]
pub struct AuthnSession {
    pub(crate) peer: PeerSessionConfig,
    pub(crate) stream: Tls13Stream,
    msg_ctx: Vec<u8>,
    transcript_hash: Vec<u8>,
    dh_secret: [u8; 32],

}

#[allow(dead_code)]
impl EarlySession {
    pub fn with_peer(peer: &PeerSessionConfig) -> Result<Self, Mutter> {
        let stream = Tls13Stream::new(&peer.tls_addr)?;
        Ok(Self {
            peer: peer.clone(),
            stream
        })
    }
}
