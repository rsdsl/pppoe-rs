use byteorder::{ByteOrder, NetworkEndian as NE};

use std::convert::TryFrom;

use crate::error::ParseError;

pub const LCP: u16 = 0xc021;
pub const PAP: u16 = 0xc023;
pub const CHAP: u16 = 0xc223;

#[repr(u16)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Protocol {
    Lcp = LCP,
    Pap = PAP,
    Chap = CHAP,
}

impl TryFrom<u16> for Protocol {
    type Error = ParseError;
    fn try_from(protocol: u16) -> Result<Self, ParseError> {
        Ok(match protocol {
            LCP => Protocol::Lcp,
            PAP => Protocol::Pap,
            CHAP => Protocol::Chap,
            _ => return Err(ParseError::InvalidPppProtocol(protocol)),
        })
    }
}

fn ensure_minimal_buffer_length(buffer: &[u8]) -> Result<(), ParseError> {
    if buffer.len() < 2 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

#[derive(Debug)]
pub struct Header<'a>(&'a [u8]);

impl<'a> Header<'a> {
    pub fn with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        ensure_minimal_buffer_length(buffer)?;
        if buffer[0] & 0x01 != 0x00 || buffer[1] & 0x01 != 0x01 {
            let protocol = NE::read_u16(&buffer[..2]);
            return Err(ParseError::InvalidPppProtocol(protocol));
        }

        Ok(Header(buffer))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }

    pub fn get_ref(&self) -> &[u8] {
        self.0
    }

    pub fn protocol(&self) -> u16 {
        NE::read_u16(&self.0[..2])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[2..]
    }
}

pub struct HeaderBuilder<'a>(&'a mut [u8]);

impl<'a> HeaderBuilder<'a> {
    pub fn protocol(&self) -> u16 {
        NE::read_u16(&self.0[..2])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[2..]
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        NE::write_u16(&mut self.0[..2], protocol as u16);
    }

    pub fn create_packet(buffer: &'a mut [u8], protocol: Protocol) -> Result<Self, ParseError> {
        ensure_minimal_buffer_length(buffer)?;

        NE::write_u16(&mut buffer[..2], protocol as u16);

        Ok(HeaderBuilder(buffer))
    }

    pub fn get_ref_mut(&mut self) -> &mut [u8] {
        self.0
    }

    pub fn build(self) -> Result<Header<'a>, ParseError> {
        Header::with_buffer(self.0)
    }
}
