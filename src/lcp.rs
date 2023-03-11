use byteorder::{ByteOrder, NetworkEndian as NE};

use std::cmp::min;
use std::convert::TryFrom;

use crate::auth;
use crate::error::ParseError;

pub const CONFIGURE_REQUEST: u8 = 1;
pub const CONFIGURE_ACK: u8 = 2;
pub const CONFIGURE_NAK: u8 = 3;
pub const CONFIGURE_REJECT: u8 = 4;
pub const TERMINATE_REQUEST: u8 = 5;
pub const TERMINATE_ACK: u8 = 6;
pub const CODE_REJECT: u8 = 7;
pub const PROTOCOL_REJECT: u8 = 8;
pub const ECHO_REQUEST: u8 = 9;
pub const ECHO_REPLY: u8 = 10;
pub const DISCARD_REQUEST: u8 = 11;

#[repr(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Code {
    ConfigureRequest = CONFIGURE_REQUEST,
    ConfigureAck = CONFIGURE_ACK,
    ConfigureNak = CONFIGURE_NAK,
    ConfigureReject = CONFIGURE_REJECT,
    TerminateRequest = TERMINATE_REQUEST,
    TerminateAck = TERMINATE_ACK,
    CodeReject = CODE_REJECT,
    ProtocolReject = PROTOCOL_REJECT,
    EchoRequest = ECHO_REQUEST,
    EchoReply = ECHO_REPLY,
    DiscardRequest = DISCARD_REQUEST,
}

impl TryFrom<u8> for Code {
    type Error = ParseError;
    fn try_from(code: u8) -> Result<Self, ParseError> {
        Ok(match code {
            CONFIGURE_REQUEST => Code::ConfigureRequest,
            CONFIGURE_ACK => Code::ConfigureAck,
            CONFIGURE_NAK => Code::ConfigureNak,
            CONFIGURE_REJECT => Code::ConfigureReject,
            TERMINATE_REQUEST => Code::TerminateRequest,
            TERMINATE_ACK => Code::TerminateAck,
            CODE_REJECT => Code::CodeReject,
            PROTOCOL_REJECT => Code::ProtocolReject,
            ECHO_REQUEST => Code::EchoRequest,
            ECHO_REPLY => Code::EchoReply,
            DISCARD_REQUEST => Code::DiscardRequest,
            _ => return Err(ParseError::InvalidLcpCode(code)),
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
        if length + 4 > buffer.len() {
            return Err(ParseError::PayloadLengthOutOfBound {
                actual_packet_length: buffer.len() as u16,
                payload_length: length as u16,
            });
        }

        Ok(Header(buffer))
    }

    pub fn configure_request_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::ConfigureRequest))
    }

    pub fn configure_ack_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::ConfigureAck))
    }

    pub fn configure_nak_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::ConfigureNak))
    }

    pub fn configure_reject_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::ConfigureReject))
    }

    pub fn terminate_request_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::TerminateRequest))
    }

    pub fn terminate_ack_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::TerminateAck))
    }

    pub fn code_reject_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::CodeReject))
    }

    pub fn protocol_reject_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::ProtocolReject))
    }

    pub fn echo_request_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::EchoRequest))
    }

    pub fn echo_reply_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::EchoReply))
    }

    pub fn discard_request_with_buffer(buffer: &'a [u8]) -> Result<Self, ParseError> {
        Self::with_buffer_and_code(buffer, Some(Code::DiscardRequest))
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
        unsafe { self.set_len(0) };
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

    pub fn create_configure_request(buffer: &'a mut [u8]) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::ConfigureRequest, rand::random())
    }

    pub fn create_configure_ack(buffer: &'a mut [u8], identifier: u8) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::ConfigureAck, identifier)
    }

    pub fn create_configure_nak(buffer: &'a mut [u8], identifier: u8) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::ConfigureAck, identifier)
    }

    pub fn create_configure_reject(
        buffer: &'a mut [u8],
        identifier: u8,
    ) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::ConfigureReject, identifier)
    }

    pub fn create_terminate_request(buffer: &'a mut [u8]) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::TerminateRequest, rand::random())
    }

    pub fn create_terminate_ack(buffer: &'a mut [u8], identifier: u8) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::TerminateAck, identifier)
    }

    pub fn create_code_reject(buffer: &'a mut [u8], identifier: u8) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::CodeReject, identifier)
    }

    pub fn create_protocol_reject(
        buffer: &'a mut [u8],
        identifier: u8,
    ) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::ProtocolReject, identifier)
    }

    pub fn create_echo_request(buffer: &'a mut [u8]) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::EchoRequest, rand::random())
    }

    pub fn create_echo_reply(buffer: &'a mut [u8], identifier: u8) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::EchoReply, identifier)
    }

    pub fn create_discard_request(buffer: &'a mut [u8]) -> Result<Self, ParseError> {
        Self::create_packet(buffer, Code::DiscardRequest, rand::random())
    }

    pub fn get_ref_mut(&mut self) -> &mut [u8] {
        self.0
    }

    pub fn build(self) -> Result<Header<'a>, ParseError> {
        Header::with_buffer(self.0)
    }
}

fn ensure_minimal_option_length(buffer: &[u8]) -> Result<(), ParseError> {
    if buffer.len() < 2 {
        return Err(ParseError::BufferTooSmall(buffer.len()));
    }
    Ok(())
}

pub const MRU: u8 = 1;
pub const AUTH_PROTOCOL: u8 = 3;
pub const QUALITY_PROTOCOL: u8 = 4;
pub const MAGIC_NUMBER: u8 = 5;
pub const PFC: u8 = 7;
pub const ACFC: u8 = 8;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfigOption<'a> {
    Mru(u16),
    AuthProtocol(auth::Protocol<'a>),
    QualityProtocol(&'a [u8]),
    MagicNumber(u32),
    Pfc,
    Acfc,
}

impl<'a> ConfigOption<'a> {
    fn from_buffer(option: &'a [u8]) -> Result<(ConfigOption<'a>, &'a [u8]), ParseError> {
        ensure_minimal_option_length(option)?;

        Ok(match option[0] {
            MRU => {
                // constant length
                if option[1] != 4 {
                    return Err(ParseError::InvalidOptionLength(option[1]));
                }

                (ConfigOption::Mru(NE::read_u16(&option[2..4])), &option[4..])
            }
            AUTH_PROTOCOL => {
                if option[1] < 4 {
                    return Err(ParseError::InvalidOptionLength(option[1]));
                }

                let auth_protocol = auth::Protocol::from_buffer(&option[2..option[1] as usize])?;
                (
                    ConfigOption::AuthProtocol(auth_protocol),
                    &option[option[1] as usize..],
                )
            }
            QUALITY_PROTOCOL => {
                if option[1] < 4 {
                    return Err(ParseError::InvalidOptionLength(option[1]));
                }

                let quality_protocol = NE::read_u16(&option[2..4]);
                if quality_protocol != 0xc025 {
                    return Err(ParseError::InvalidQualityProtocol(quality_protocol));
                }

                (
                    ConfigOption::QualityProtocol(&option[4..option[1] as usize]),
                    &option[option[1] as usize..],
                )
            }
            MAGIC_NUMBER => {
                // constant length
                if option[1] != 6 {
                    return Err(ParseError::InvalidOptionLength(option[1]));
                }

                (
                    ConfigOption::MagicNumber(NE::read_u32(&option[2..6])),
                    &option[6..],
                )
            }
            PFC => {
                // constant length
                if option[1] != 2 {
                    return Err(ParseError::InvalidOptionLength(option[1]));
                }

                (ConfigOption::Pfc, &option[2..])
            }
            ACFC => {
                // constant length
                if option[1] != 2 {
                    return Err(ParseError::InvalidOptionLength(option[1]));
                }

                (ConfigOption::Acfc, &option[2..])
            }
            _ => return Err(ParseError::InvalidOptionType(option[0])),
        })
    }

    fn code(&self) -> u8 {
        match self {
            ConfigOption::Mru(_) => MRU,
            ConfigOption::AuthProtocol(_) => AUTH_PROTOCOL,
            ConfigOption::QualityProtocol(_) => QUALITY_PROTOCOL,
            ConfigOption::MagicNumber(_) => MAGIC_NUMBER,
            ConfigOption::Pfc => PFC,
            ConfigOption::Acfc => ACFC,
        }
    }

    fn write_to_buffer(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        ensure_minimal_option_length(buf)?;

        buf[0] = self.code();

        match *self {
            ConfigOption::Mru(mru) => {
                // constant length
                buf[1] = 4;
                NE::write_u16(&mut buf[2..4], mru);
            }
            ConfigOption::AuthProtocol(ref auth_protocol) => {
                buf[1] = 4 + auth_protocol.data().map(|v| v.len()).unwrap_or(0) as u8;
                NE::write_u16(&mut buf[2..4], auth_protocol.protocol());

                if let Some(data) = auth_protocol.data() {
                    // todo: bounds check, returning BufferTooSmall error
                    let limit = min(buf.len(), 4 + data.len());
                    buf[4..limit].copy_from_slice(data);
                }
            }
            ConfigOption::QualityProtocol(data) => {
                buf[1] = 4 + data.len() as u8;
                NE::write_u16(&mut buf[2..4], 0xc025);

                let limit = min(buf.len(), 4 + data.len());
                buf[4..limit].copy_from_slice(data);
            }
            ConfigOption::MagicNumber(magic) => {
                // constant length
                buf[1] = 6;
                NE::write_u32(&mut buf[2..6], magic);
            }
            ConfigOption::Pfc => {
                // constant length
                buf[1] = 2;
            }
            ConfigOption::Acfc => {
                // constant length
                buf[1] = 2;
            }
        }

        Ok(buf[1] as usize)
    }
}

#[derive(Debug, Default)]
pub struct ConfigOptions<'a>(Vec<ConfigOption<'a>>);

impl<'a> ConfigOptions<'a> {
    pub fn add_option(&mut self, option: ConfigOption<'a>) {
        self.0.push(option);
    }

    pub fn write_to_buffer(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        let mut n = 0;
        for option in &self.0 {
            n += option.write_to_buffer(&mut buf[n..])?;
        }

        Ok(n)
    }
}

pub struct ConfigOptionIterator<'a> {
    payload: &'a [u8],
}

impl<'a> ConfigOptionIterator<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        ConfigOptionIterator { payload }
    }
}

impl<'a> Iterator for ConfigOptionIterator<'a> {
    type Item = ConfigOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let (opt, payload) = ConfigOption::from_buffer(self.payload).unwrap();
        self.payload = payload;
        Some(opt)
    }
}
