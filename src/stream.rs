use crate::cfg::PeerSessionConfig;
use crate::err::Error;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[allow(dead_code)]
pub trait Stream {
    fn read(&mut self, count: usize, buf: &mut Vec<u8>) -> Result<usize, Error>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error>;
    fn shutdown(&mut self) -> Result<(), Error>;
    fn stop_write(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct TlsStream {
    pub(crate) stream: TcpStream,
}

impl TlsStream {
    const MAX_BLOCKED_RETRY: u32 = 26;
    pub fn new(server: &str) -> Result<TlsStream, Error> {
        let server_sock_addresses = server
            .to_socket_addrs()
            .map_err(|_| Error::BadNetworkAddress)?;
        for serv_sock_addr in server_sock_addresses {
            match TcpStream::connect(serv_sock_addr) {
                Ok(sock) => {
                    let _ = sock.set_read_timeout(Some(Duration::from_millis(60)));
                    return Ok(Self { stream: sock });
                }
                Err(e) => {
                    log::error!("error: {e:#?}");
                }
            }
        }
        log::info!("TlsStream created!");
        Err(Error::TlsConnection)
    }

    pub fn fulfill(&mut self, required: usize, buf: &mut Vec<u8>) -> Result<usize, Error> {
        let buf_len_on_entry = buf.len();
        while buf.len() - buf_len_on_entry < required {
            self.read(required, buf)?;
        }
        Ok(buf.len() - buf_len_on_entry)
    }
}

impl Stream for TlsStream {
    fn read(&mut self, count: usize, buf: &mut Vec<u8>) -> Result<usize, Error> {
        let buf_len_on_enter = buf.len();
        let mut blocked = 0;
        loop {
            match self.stream.read_to_end(buf) {
                Ok(0) => {
                    let copied = buf.len() - buf_len_on_enter;
                    return Ok(copied);
                }
                Ok(_n) => {
                    assert!(_n > 0);
                    let copied = buf.len() - buf_len_on_enter;
                    if copied > count {
                        return Ok(copied);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let copied = buf.len() - buf_len_on_enter;
                    if blocked > Self::MAX_BLOCKED_RETRY / 2 && copied > 0 {
                        return Ok(copied);
                    }
                    blocked += 1;
                    // log::warn!("block retry count: {blocked}");
                    if blocked > Self::MAX_BLOCKED_RETRY {
                        return Error::ProbablyEmptyStream.into();
                    }
                    continue;
                }
                Err(_e) => {
                    return Error::StreamError.into();
                }
            }
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.stream.write(buf).map_err(|_| Error::StreamWriteError)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        let _ = self
            .stream
            .shutdown(Shutdown::Read)
            .map_err(|_| Error::StreamShutdownError);
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| Error::StreamShutdownError)
    }

    fn stop_write(&mut self) -> Result<(), Error> {
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| Error::StreamShutdownError)
    }
}

#[derive(Debug)]
pub struct TlsConnection {
    pub(crate) stream: TlsStream,
}

impl TlsConnection {
    pub fn with_peer(peer: &PeerSessionConfig) -> Result<Self, Error> {
        let stream = TlsStream::new(&peer.tls_addr)?;
        Ok(Self { stream })
    }
}
