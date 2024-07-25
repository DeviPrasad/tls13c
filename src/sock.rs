use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};

use crate::err::Mutter;

#[allow(dead_code)]
pub trait Stream {
    fn read(&mut self, count: usize, buf: &mut Vec<u8>) -> Result<usize, Mutter>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Mutter>;
    fn shutdown(&mut self) -> Result<(), Mutter>;
    fn stop_write(&mut self) -> Result<(), Mutter>;
}

#[derive(Debug)]
pub struct Tls13Stream {
    stream: TcpStream,
}

impl Tls13Stream {
    pub fn new(server: &str) -> Result<Tls13Stream, Mutter> {
        let server_sock_addresses = server.to_socket_addrs()
                                          .map_err(|_| Mutter::BadNetworkAddress)?;
        for serv_sock_addr in server_sock_addresses {
            let sock = TcpStream::connect(serv_sock_addr)
                .map_err(|_| Mutter::SocketPropertyError)?;
            return Ok(Self {
                stream: sock
            })
        }
        Err(Mutter::TlsConnection)
    }
}

impl Stream for Tls13Stream {
    fn read(&mut self, _count: usize, mut buf: &mut Vec<u8>) -> Result<usize, Mutter> {
        let mut copied = 0;
        let mut retry = 0;

        let _ = self.stream.set_read_timeout(Some(core::time::Duration::from_secs(20)));
        loop {
            return match self.stream.read_to_end(&mut buf) {
                Ok(0) => {
                    retry += 1;
                    if retry < 2 {
                        continue
                    } else {
                        Ok(copied)
                    }
                },
                Ok(n) => {
                    if copied < 512 {
                        log::info!("Tls13Stream::read - {copied}");
                        copied += n;
                        continue
                    } else {
                        Ok(copied)
                    }
                },
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
    fn write(&mut self, buf: &[u8]) -> Result<usize, Mutter> {
        self.stream.write(buf)
            .map_err(|_| Mutter::StreamWriteError)
    }

    fn shutdown(&mut self) -> Result<(), Mutter> {
        let _ = self.stream.shutdown(Shutdown::Read)
                    .map_err(|_| Mutter::StreamShutdownError);
        self.stream.shutdown(Shutdown::Write)
            .map_err(|_| Mutter::StreamShutdownError)
    }

    fn stop_write(&mut self) -> Result<(), Mutter> {
        self.stream.shutdown(Shutdown::Write)
            .map_err(|_| Mutter::StreamShutdownError)
    }
}
