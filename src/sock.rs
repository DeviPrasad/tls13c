use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::err::Mutter;

pub(crate) type MilliSec = u64;

#[allow(dead_code)]
pub trait Stream {
    async fn read(&self, count: usize, buf: &mut [u8]) -> Result<usize, Mutter>;
    async fn read_timeout(&self, duration: MilliSec, count: usize, buf: &mut [u8]) -> Result<usize, Mutter>;
    async fn write(&self, buf: &[u8]) -> Result<usize, Mutter>;
    async fn shutdown(&mut self) -> Result<(), Mutter>;
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Transport {
    stream: TcpStream,
}

#[allow(dead_code)]
impl Stream for Transport {
    async fn read(&self, count: usize, mut buf: &mut [u8]) -> Result<usize, Mutter> {
        let mut copied: usize = 0;
        loop {
            self.readable().await?;
            return match self.stream.try_read_buf(&mut buf) {
                Ok(0) => {
                    log::info!("stream empty!");
                    Ok(copied)
                }
                Ok(n) => {
                    copied += n;
                    if copied >= count {
                        Ok(copied)
                    } else {
                        continue;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    log::error!("error: {e:#?}");
                    Err(Mutter::StreamError)
                }
            }
        }
    }

    async fn read_timeout(&self, duration: MilliSec, count: usize, mut buf: &mut [u8]) -> Result<usize, Mutter> {
        timeout(Duration::from_millis(duration), self.read(count, &mut buf))
            .await
            .map_err(|_| Mutter::StreamTimeout)?
    }

    async fn write(&self, buf: &[u8]) -> Result<usize, Mutter> {
        let _ = self.stream.writable().await;
        self.stream.try_write(buf)
            .map_err(|_| Mutter::StreamWriteError)
    }

    async fn shutdown(&mut self) -> Result<(), Mutter> {
        self.stream.shutdown()
            .await
            .map_err(|_| Mutter::StreamShutdownError)
    }
}

#[allow(dead_code)]
impl Transport {
    pub async fn new(server: &str) -> Result<Transport, Mutter> {
        let server_sock_addresses = server.to_socket_addrs()
                                          .map_err(|_| Mutter::BadNetworkAddress)?;
        for serv_sock_addr in server_sock_addresses {
            let socket = TcpSocket::new_v4().map_err(|_| Mutter::TlsConnection)?;
            if let Ok(sock_stream) = socket.connect(serv_sock_addr).await {
                sock_stream.nodelay().map_err(|_| Mutter::SocketPropertyError)?;
                return Ok(Transport {
                    stream: sock_stream,
                })
            }
        }
        Err(Mutter::TlsConnection)
    }

    pub async fn readable(&self) -> Result<(), Mutter> {
        self.stream.readable().await
            .map_err(|_| Mutter::StreamReadinessError)
            .map(|_| ())
    }
}
