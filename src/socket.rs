use crate::packet::{PPPOE_DISCOVERY, PPPOE_SESSION};
use pppoe_sys::{control, pppoe};

use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::{fs, mem, num};

#[cfg(feature = "async")]
use mio::{event::Evented, unix::EventedFd, Poll, PollOpt, Ready, Token};

#[derive(Debug)]
pub struct Socket {
    connection: pppoe::Connection,
}

fn c_call_with_os_error<F>(call: F) -> io::Result<()>
where
    F: Fn() -> libc::c_int,
{
    let ret = call();

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn set_nonblock(fd: libc::c_int) -> io::Result<()> {
    c_call_with_os_error(|| unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
    })
}

// TODO: Check std::net Sockets methods and impl them for this if applicable
impl Socket {
    pub fn on_interface(interface_name: &str) -> io::Result<Self> {
        control::init()?;

        let mut connection = pppoe::Connection::new();
        connection.set_interface_name(interface_name)?;
        pppoe::connection_data_init(&mut connection, None)?;

        #[cfg(feature = "async")]
        set_nonblock(connection.raw_socket())?;

        Ok(Socket { connection })
    }

    fn raw_socket(&self) -> RawFd {
        self.connection.raw_socket()
    }

    pub fn connect_session(
        &mut self,
        session_id: num::NonZeroU16,
        remote_mac: [u8; 6],
    ) -> io::Result<RawFd> {
        self.connection
            .connect(session_id, remote_mac)
            .map(|_| self.connection.pppoe_socket())
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.connection.mac_address()
    }

    pub fn set_nonblock(&self) -> io::Result<()> {
        set_nonblock(self.raw_socket())
    }

    pub fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        let mut fd = unsafe { fs::File::from_raw_fd(self.raw_socket()) };
        let ret = fd.write(buffer);
        mem::forget(fd);
        ret
    }

    pub fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut fd = unsafe { fs::File::from_raw_fd(self.raw_socket()) };
            let ret = fd.read(buffer);
            mem::forget(fd);

            let ether_type = u16::from_be_bytes(buffer[12..14].try_into().unwrap());
            if ether_type == PPPOE_DISCOVERY || ether_type == PPPOE_SESSION {
                return ret;
            }
        }
    }

    pub fn close(&mut self) {
        self.connection.close_raw_socket()
    }
}

#[cfg(feature = "async")]
impl Evented for Socket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.raw_socket()).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.raw_socket()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.raw_socket()).deregister(poll)
    }
}
