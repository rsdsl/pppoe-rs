use byteorder::{ByteOrder, NetworkEndian as NE};

use crate::error::ParseError;

fn ensure_minimal_buffer_length(buffer: &[u8]) -> Result<(), ParseError> {
    if buffer.len() < 2 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

#[derive(Debug)]
pub struct PppHeader<'a>(&'a [u8]);

impl<'a> PppHeader<'a> {
    pub fn with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        ensure_minimal_buffer_length(buffer)?;
        if buffer[0] & 0x01 != 0 || buffer[1] & 0x80 != 0x80 {
            let protocol = NE::read_u16(&buffer[..2]);
            return Err(ParseError::InvalidPppProtocol(protocol));
        }

        Ok(PppHeader(buffer))
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
