use byteorder::{ByteOrder, NetworkEndian as NE};

use std::convert::TryFrom;

use crate::error::ParseError;

pub const LCP: u16 = 0xc021;
pub const PAP: u16 = 0xc023;
pub const SHIVA_PAP: u16 = 0xc027;
pub const VSAP: u16 = 0xc05b;
pub const CHAP: u16 = 0xc223;
pub const RSAAP: u16 = 0xc225;
pub const EAP: u16 = 0xc227;
pub const PROPAP1: u16 = 0xc281;
pub const PROPAP2: u16 = 0xc283;
pub const PNIDAP: u16 = 0xc481;
pub const IPCP: u16 = 0x8021;
pub const IPV4: u16 = 0x0021;

#[repr(u16)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Protocol {
    Lcp = LCP,
    Pap = PAP,
    ShivaPap = SHIVA_PAP,
    Vsap = VSAP,
    Chap = CHAP,
    RsaAp = RSAAP,
    Eap = EAP,
    PropAp1 = PROPAP1,
    PropAp2 = PROPAP2,
    PNIdAp = PNIDAP,
    Ipcp = IPCP,
    Ipv4 = IPV4,
}

impl TryFrom<u16> for Protocol {
    type Error = ParseError;
    fn try_from(protocol: u16) -> Result<Self, ParseError> {
        Ok(match protocol {
            LCP => Protocol::Lcp,
            PAP => Protocol::Pap,
            SHIVA_PAP => Protocol::ShivaPap,
            VSAP => Protocol::Vsap,
            CHAP => Protocol::Chap,
            RSAAP => Protocol::RsaAp,
            EAP => Protocol::Eap,
            PROPAP1 => Protocol::PropAp1,
            PROPAP2 => Protocol::PropAp2,
            PNIDAP => Protocol::PNIdAp,
            IPCP => Protocol::Ipcp,
            IPV4 => Protocol::Ipv4,
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
