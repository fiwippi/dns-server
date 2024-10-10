use std::{error::Error, net::UdpSocket};

// DNS based largely on RFC 1035 which
// supports only questions and answers
mod dns {
    use std::{
        error::Error,
        io::{Cursor, Read},
    };

    mod flags {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        pub const QR: u8 = 0b10000000;
        pub const OPCODE: u8 = 0b01111000;
        pub const AA: u8 = 0b00000100;
        pub const TC: u8 = 0b00000010;
        pub const RD: u8 = 0b00000001;
        pub const RA: u8 = 0b10000000;
        // (the Z bits are reserved) 0b01110000;
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
        pub id: u16,
        pub is_query: bool, // If false, this is a response
        pub opcode: Opcode,
        pub is_authoritative_answer: bool,
        pub truncated: bool,
        pub recursion_desired: bool,
        pub recursion_available: bool,
        pub response_code: ResponseCode,
        pub questions: u16,
        pub answers: u16,
    }

    impl Header {
        pub fn parse(buf: &[u8]) -> Result<Header, Box<dyn Error>> {
            if buf.len() != 12 {
                return Err(Box::<dyn Error>::from("Slice is not 12 bytes long"));
            }

            Ok(Self {
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |                      ID                       |
                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                id: u16::from_be_bytes([buf[0], buf[1]]),

                // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
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
                questions: u16::from_be_bytes([buf[4], buf[5]]),
                answers: u16::from_be_bytes([buf[6], buf[7]]),
            })
        }
    }

    #[derive(Debug)]
    pub enum QType {
        A,
    }

    impl TryFrom<u16> for QType {
        type Error = String;

        fn try_from(kind: u16) -> Result<Self, Self::Error> {
            match kind {
                1 => Ok(Self::A),
                _ => Err(format!("invalid qtype: {kind}")),
            }
        }
    }

    #[derive(Debug)]
    pub enum QClass {
        Internet,
    }

    impl TryFrom<u16> for QClass {
        type Error = String;

        fn try_from(class: u16) -> Result<Self, Self::Error> {
            match class {
                1 => Ok(Self::Internet),
                _ => Err(format!("invalid qclass: {class}")),
            }
        }
    }

    // FIX I would like a Question::parse() method, but
    //     the question doesn't have a set length, so I
    //     can't provide it a pre-read slice using Cursor
    #[derive(Debug)]
    pub struct Question {
        name: Vec<String>,
        qtype: QType,
        qclass: QClass,
    }

    #[derive(Debug)]
    pub struct Message {
        header: Header,
        questions: Vec<Question>,
    }

    impl Message {
        pub fn parse(buf: &[u8]) -> Result<Message, Box<dyn Error>> {
            let mut cursor = Cursor::new(&buf[..]);

            // Parse the header
            let mut header_buf = [0; 12];
            cursor.read_exact(&mut header_buf)?;
            let header = Header::parse(&header_buf)?;

            // Parse the questions
            let mut questions: Vec<Question> = Vec::new();
            for _ in 0..header.questions {
                let mut labels: Vec<String> = Vec::new();
                let mut name_len_buf = [0; 1];
                cursor.read_exact(&mut name_len_buf)?;
                while name_len_buf[0] != 0 {
                    let mut label_buf = vec![0; name_len_buf[0] as usize];
                    cursor.read_exact(&mut label_buf)?;
                    labels.push(String::from_utf8(label_buf)?);
                    cursor.read_exact(&mut name_len_buf)?;
                }

                let mut qtype_buf = [0; 2];
                let mut qclass_buf = [0; 2];
                cursor.read_exact(&mut qtype_buf)?;
                cursor.read_exact(&mut qclass_buf)?;

                let q = Question {
                    name: labels,
                    qtype: QType::try_from(u16::from_be_bytes(qtype_buf))?,
                    qclass: QClass::try_from(u16::from_be_bytes(qclass_buf))?,
                };
                questions.push(q);
            }

            //

            Ok(Self { header, questions })
        }
    }
}

// Run using `cargo run & dig @127.0.0.1 -p 5300 fiwippi.net`
fn main() -> Result<(), Box<dyn Error>> {
    // Bind to a UDP socket
    let socket = UdpSocket::bind("127.0.0.1:5300")?;

    // Receive the data sent as part of the UDP packet,
    // DNS defines the max packet size to be 512 bytes
    // as part of RFC 1035
    let mut buf = [0; 512];
    let (size, _) = socket.recv_from(&mut buf)?;

    // Parse the message
    let msg = dns::Message::parse(&buf[..size]);
    println!("{msg:?}");

    Ok(())
}
