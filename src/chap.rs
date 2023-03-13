use byteorder::{ByteOrder, NetworkEndian as NE};

use std::convert::TryFrom;

use crate::error::ParseError;

pub const CHALLENGE: u8 = 1;
pub const RESPONSE: u8 = 2;
pub const SUCCESS: u8 = 3;
pub const FAILURE: u8 = 4;

#[repr(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Code {
    Challenge = CHALLENGE,
    Response = RESPONSE,
    Success = SUCCESS,
    Failure = FAILURE,
}

impl TryFrom<u8> for Code {
    type Error = ParseError;
    fn try_from(code: u8) -> Result<Self, ParseError> {
        Ok(match code {
            CHALLENGE => Code::Challenge,
            RESPONSE => Code::Response,
            SUCCESS => Code::Success,
            FAILURE => Code::Failure,
            _ => return Err(ParseError::InvalidChapCode(code)),
        })
    }
}

fn ensure_minimal_buffer_length(buffer: &[u8]) -> Result<(), ParseError> {
    if buffer.len() < 4 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

#[derive(Debug)]
pub struct Header<'a>(&'a [u8]);

impl<'a> Header<'a> {
    pub fn with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, None)
    }

    pub fn with_buffer_and_code(
        buffer: &'a [u8],
        expected_code: Option<Code>,
    ) -> Result<Header<'a>, ParseError> {
        ensure_minimal_buffer_length(buffer)?;

        let code = Code::try_from(buffer[0])?;
        if let Some(expected_code) = expected_code {
            if code != expected_code {
                return Err(ParseError::UnexpectedCode(code as u8));
            }
        }

        let length = usize::from(NE::read_u16(&buffer[2..4]));
        if length > buffer.len() {
            return Err(ParseError::PayloadLengthOutOfBound {
                actual_packet_length: buffer.len() as u16,
                payload_length: length as u16,
            });
        }

        Ok(Header(buffer))
    }

    pub fn challenge_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::Challenge))
    }

    pub fn response_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::Response))
    }

    pub fn success_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::Success))
    }

    pub fn failure_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::Failure))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }

    pub fn get_ref(&self) -> &[u8] {
        self.0
    }

    pub fn code(&self) -> u8 {
        self.0[0]
    }

    pub fn identifier(&self) -> u8 {
        self.0[1]
    }

    pub fn len(&self) -> usize {
        usize::from(NE::read_u16(&self.0[2..4]))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[4..self.len()]
    }
}

pub struct HeaderBuilder<'a>(&'a mut [u8]);

impl<'a> HeaderBuilder<'a> {
    pub fn code(&self) -> u8 {
        self.0[0]
    }

    pub fn identifier(&self) -> u8 {
        self.0[1]
    }

    pub fn len(&self) -> usize {
        usize::from(NE::read_u16(&self.0[2..4]))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[4..self.len()]
    }

    pub fn set_code(&mut self, code: Code) {
        self.0[0] = code as u8;
    }

    pub fn set_identifier(&mut self, identifier: u8) {
        self.0[1] = identifier;
    }

    unsafe fn set_len(&mut self, new_length: u16) {
        NE::write_u16(&mut self.0[2..4], new_length)
    }

    pub fn clear_payload(&mut self) {
        unsafe { self.set_len(4) }
    }

    pub fn create_packet(
        buffer: &'a mut [u8],
        code: Code,
        identifier: u8,
    ) -> Result<Self, ParseError> {
        ensure_minimal_buffer_length(buffer)?;

        let length = 4 + buffer[4..].len() as u16;

        buffer[0] = code as u8;
        buffer[1] = identifier;
        NE::write_u16(&mut buffer[2..4], length);

        Ok(HeaderBuilder(buffer))
    }

    pub fn create_challenge(buffer: &'a mut [u8]) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::Challenge, rand::random())
    }

    pub fn create_response(buffer: &'a mut [u8], identifier: u8) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::Response, identifier)
    }

    pub fn get_ref_mut(&mut self) -> &mut [u8] {
        self.0
    }

    pub fn build(self) -> Result<Header<'a>, ParseError> {
        Header::with_buffer(self.0)
    }
}
