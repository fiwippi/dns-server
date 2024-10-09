use std::{
    error::Error,
    io::{Cursor, Read},
    net::UdpSocket,
};

// TODO CLI command to bind to a specific (host, port) combination
// TODO Support security awareness

// DNS based on RFC 1035 and RFC 2535 but with
// no support for security awareness
mod dns {
    use std::error::Error;

    mod flags {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        pub const QR: u8 = 0b10000000;
        pub const OPCODE: u8 = 0b01111000;
        pub const AA: u8 = 0b00000100;
        pub const TC: u8 = 0b00000010;
        pub const RD: u8 = 0b00000001;
        pub const Z: u8 = 0b01000000;
        pub const AD: u8 = 0b00100000;
        pub const CD: u8 = 0b00010000;
        pub const RCODE: u8 = 0b00001111;
    }

    #[derive(Debug)]
    pub enum Opcode {
        StandardQuery,
        InverseQuery,
        ServerStatusRequest,
    }

    impl TryFrom<u8> for Opcode {
        type Error = String;

        fn try_from(code: u8) -> Result<Self, Self::Error> {
            match code {
                0 => Ok(Self::StandardQuery),
                1 => Ok(Self::InverseQuery),
                2 => Ok(Self::ServerStatusRequest),
                _ => Err(format!("invalid opcode: {code}")),
            }
        }
    }

    #[derive(Debug)]
    pub enum ResponseCode {
        NoError,
        FormatError,
        ServerFailure,
        NameError,
        NotImplemented,
        Refused,
    }

    impl TryFrom<u8> for ResponseCode {
        type Error = String;

        fn try_from(code: u8) -> Result<Self, Self::Error> {
            match code {
                0 => Ok(Self::NoError),
                1 => Ok(Self::FormatError),
                2 => Ok(Self::ServerFailure),
                3 => Ok(Self::NameError),
                4 => Ok(Self::NotImplemented),
                5 => Ok(Self::Refused),
                _ => Err(format!("invalid response code: {code}")),
            }
        }
    }

    #[derive(Debug)]
    pub struct Header {
        id: u16,
        is_query: bool, // If false, this is a response
        opcode: Opcode,
        is_authoritative_answer: bool,
        truncated: bool,
        recursion_desired: bool,
        recursion_available: bool,
        response_code: ResponseCode,
        questions: u16,
        answers: u16,
        nameservers: u16,
        additional: u16,
    }

    impl Header {
        pub fn parse(buf: &[u8]) -> Result<Header, Box<dyn Error>> {
            if buf.len() != 12 {
                return Err(Box::<dyn Error>::from("Slice is not 12 bytes long"));
            }
            // As per the DNS RFC, the Z value must
            // be zero for all queries and responses
            let z = buf[3] & flags::Z;
            if z > 0 {
                return Err(Box::<dyn Error>::from("Z is not zeroed"));
            }

            Ok(Self {
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |                      ID                       |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                id: u16::from_be_bytes([buf[0], buf[1]]),

                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                is_query: (buf[2] & flags::QR) > 0,
                opcode: Opcode::try_from(u8::from_be((buf[2] & flags::OPCODE) << 1))?,
                is_authoritative_answer: (buf[2] & flags::AA) > 0,
                truncated: (buf[2] & flags::TC) > 0,
                recursion_desired: (buf[2] & flags::RD) > 0,
                recursion_available: false, // We currently don't support recursion
                response_code: ResponseCode::try_from(u8::from_be((buf[3] & flags::RCODE) << 4))?,

                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |                    QDCOUNT                    |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |                    ANCOUNT                    |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |                    NSCOUNT                    |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |                    ARCOUNT                    |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                questions: u16::from_be_bytes([buf[4], buf[5]]),
                answers: u16::from_be_bytes([buf[6], buf[7]]),
                nameservers: u16::from_be_bytes([buf[8], buf[9]]),
                additional: u16::from_be_bytes([buf[10], buf[11]]),
            })
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Bind to a UDP socket
    let socket = UdpSocket::bind("127.0.0.1:5300")?;

    // Receive the data sent as part of the UDP packet,
    // DNS defines the max packet size to be 512 bytes
    // as part of RFC 1035
    let mut buf = [0; 512];
    let (size, _) = socket.recv_from(&mut buf)?;
    let mut cursor = Cursor::new(&buf[..size]);

    // Parse the header
    let mut header_buf = [0; 12];
    cursor.read_exact(&mut header_buf)?;
    let header = dns::Header::parse(&header_buf)?;

    println!("{header:?}");

    Ok(())
}
