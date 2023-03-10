use byteorder::{ByteOrder, NetworkEndian as NE};

use std::convert::TryFrom;

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
pub enum Protocol {
    Pap = PAP,
    Chap = CHAP,
}

impl TryFrom<&[u8]> for Protocol {
    type Error = ParseError;
    fn try_from(protocol: &[u8]) -> Result<Self, ParseError> {
        ensure_minimal_buffer_length(protocol)?;

        let auth_protocol = NE::read_u16(&protocol[..2]);
        match auth_protocol {
            PAP => Ok(Protocol::Pap),
            CHAP => Ok(Protocol::Chap),
            _ => Err(ParseError::InvalidAuthProtocol(auth_protocol)),
        }
    }
}
