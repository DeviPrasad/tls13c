use crate::cfg::PeerSessionConfig;
use crate::err::Mutter;
use crate::sock::Transport;

#[allow(dead_code)]
#[derive(Debug)]
pub struct EarlySession {
    pub(crate) peer: PeerSessionConfig,
    pub(crate) stream: Transport,
}

#[allow(dead_code)]
pub struct HandshakeSession {
    pub(crate) peer: PeerSessionConfig,
    pub(crate) stream: Transport,
    msg_ctx: Vec<u8>,
    transcript_hash: Vec<u8>,
}

#[allow(dead_code)]
pub struct AuthnSession {
    pub(crate) peer: PeerSessionConfig,
    pub(crate) stream: Transport,
    msg_ctx: Vec<u8>,
    transcript_hash: Vec<u8>,
    dh_secret: [u8; 32],

}

#[allow(dead_code)]
impl EarlySession {
    pub async fn with_peer(peer: &PeerSessionConfig) -> Result<Self, Mutter> {
        let stream = tokio::task::block_in_place(|| {
            Transport::new(&peer.tls_addr)
        });

        Ok(Self {
            peer: peer.clone(),
            stream: stream.await?,
        })
    }
}
