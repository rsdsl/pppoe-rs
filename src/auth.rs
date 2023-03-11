use byteorder::{ByteOrder, NetworkEndian as NE};

use crate::error::ParseError;
use crate::ppp::{CHAP, PAP};

fn ensure_minimal_buffer_length(buffer: &[u8]) -> Result<(), ParseError> {
    if buffer.len() < 2 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Protocol<'a> {
    Pap = PAP,
    Chap(&'a [u8]) = CHAP,
}

impl<'a> Protocol<'a> {
    pub fn data(&self) -> Option<&'a [u8]> {
        if let Protocol::Chap(data) = self {
            Some(data)
        } else {
            None
        }
    }

    pub fn protocol(&self) -> u16 {
        unsafe { *<*const _>::from(self).cast() }
    }
}

impl<'a> Protocol<'a> {
    pub fn from_buffer(protocol: &'a [u8]) -> Result<Self, ParseError> {
        ensure_minimal_buffer_length(protocol)?;

        let auth_protocol = NE::read_u16(&protocol[..2]);
        match auth_protocol {
            PAP => Ok(Protocol::Pap),
            CHAP => Ok(Protocol::Chap(&protocol[2..])),
            _ => Err(ParseError::InvalidAuthProtocol(auth_protocol)),
        }
    }
}
