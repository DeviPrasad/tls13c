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
pub struct TlsStream {
    stream: TcpStream,
}

impl TlsStream {
    pub fn new(server: &str) -> Result<TlsStream, Mutter> {
        let server_sock_addresses = server.to_socket_addrs()
                                          .map_err(|_| Mutter::BadNetworkAddress)?;
        for serv_sock_addr in server_sock_addresses {
            let sock = TcpStream::connect(serv_sock_addr)
                .map_err(|_| Mutter::SocketPropertyError)?;
            sock.set_read_timeout(Some(core::time::Duration::from_secs(3))).map_err(|e| {
                log::error!("error: {e:#?}");
                Mutter::StreamReadinessError.into()
            })?;
            return Ok(Self {
                stream: sock
            })
        }
        Err(Mutter::TlsConnection)
    }
}

impl Stream for TlsStream {
    fn read(&mut self, count: usize, mut buf: &mut Vec<u8>) -> Result<usize, Mutter> {
        let buf_len_on_enter = buf.len();
        loop
        {
            match self.stream.read_to_end(&mut buf) {
                Ok(0) => {
                    let copied = buf.len() - buf_len_on_enter;
                    return Ok(copied)
                },
                Ok(n) => {
                    let copied = buf.len() - buf_len_on_enter;
                    if n == 0 || copied > count {
                        return Ok(copied)
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let copied = buf.len() - buf_len_on_enter;
                    if copied > count {
                        return Ok(copied)
                    }
                    continue
                }
                Err(e) => {
                    log::error!("error: {e:#?}");
                    return Mutter::StreamError.into()
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
