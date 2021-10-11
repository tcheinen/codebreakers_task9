use hex_literal::hex;
use serde::{Deserialize, Serialize};
use enum_primitive_derive::Primitive;

pub trait Protocol {
    fn to_proto_bytes(self) -> Vec<u8>;
}

#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Magic {
    Start = 0x19B0A81D,
    End = 0xEDA9F5CE,
}

impl Protocol for Magic {
    fn to_proto_bytes(self) -> Vec<u8> {
        (self as u32).to_be_bytes().to_vec()
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Param {
    Cmd(Command) = 0x4D00,
    Uuid([u8; 16]) = 0x4D08,
    DirName(String) = 0x4D14,
    FileName(String) = 0x4D1C,
    Contents(String) = 0x4D20,
    More(String) = 0x4D24,
    Code(u32) = 0x4D28,
}

impl Protocol for Param {
    fn to_proto_bytes(self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            Self::Cmd(cmd) => {
                data.extend(0x4D00_u16.to_be_bytes().into_iter());
                data.extend(hex!("0002").into_iter());
                data.append(&mut cmd.to_proto_bytes());
            }
            Self::Uuid(uuid) => {
                data.extend(0x4D08_u16.to_be_bytes().into_iter());
                data.extend(hex!("0010").into_iter());
                data.extend(uuid.into_iter());
            }
            Self::DirName(s) => {
                data.extend(0x4D14_u16.to_be_bytes().into_iter());
                data.extend(((s.len() + 1) as u16).to_be_bytes());
                data.extend(s.bytes());
                data.push(0);
            }
            Self::FileName(s) => {
                data.extend(0x4D1c_u16.to_be_bytes().into_iter());
                data.extend(((s.len() + 1) as u16).to_be_bytes());
                data.extend(s.bytes());
                data.push(0);
            }
            Self::Code(code) => {
                data.extend(0x4D28_u16.to_be_bytes().into_iter());
                data.extend(hex!("0004").into_iter());
                data.extend(code.to_be_bytes());
            }
            Self::Contents(s) => {
                data.extend(0x4D20_u16.to_be_bytes().into_iter());
                data.extend(((s.len() + 1) as u16).to_be_bytes());
                data.extend(s.bytes());
                data.push(0);
            }
            Self::More(s) => {
                data.extend(0x4D24_u16.to_be_bytes().into_iter());
                data.extend(((s.len() + 1) as u16).to_be_bytes());
                data.extend(s.bytes());
                data.push(0);
            }
            _ => unimplemented!(),
        };
        data
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Command {
    Init = 0x0002,
    GetSessionFolder = 0x0003, // used in claris, seems to prompt the server to give you a temp folder for your UUID
    ListDir = 0x0004, // used in claris, takes UUID and folder and returns at least one file; unsure if it lists all;
    ReadFile = 0x0005, // used in claris, takes UUID, folder, and filename and responds with the contents
    Upload = 0x0006,
    Fin = 0x0007,
}

impl Command {
    pub fn from_u16(dt: u16) -> Self {
        match dt {
            2 => Self::Init,
            3 => Self::GetSessionFolder,
            4 => Self::ListDir,
            5 => Self::ReadFile,
            6 => Self::Upload,
            7 => Self::Fin,
            _ => panic!("lmao dont do that")
        }
    }
}

impl Protocol for Command {
    fn to_proto_bytes(self) -> Vec<u8> {
        (match self {
            Self::Init => 0x0002,
            Self::GetSessionFolder => 0x0003,
            Self::ListDir => 0x0004,
            Self::ReadFile => 0x0005,
            Self::Upload => 0x0006,
            Self::Fin => 0x0007,
        } as u16)
            .to_be_bytes()
            .to_vec()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Message {
    data: Vec<u8>,
}

impl Message {
    pub fn new() -> Self {
        Message { data: Vec::new() }
    }

    pub fn make_init(uuid: [u8; 16]) -> Self {
        Message::new()
            .append(Magic::Start)
            .append(Param::Cmd(Command::Init))
            .append(Param::Uuid(uuid))
            .append(Magic::End)
            .build()
    }

    pub fn append(&mut self, msg: impl Protocol) -> &mut Self {
        self.data.append(&mut msg.to_proto_bytes());
        self
    }
    pub fn build(&mut self) -> Self {
        // TODO add sanity checks; begin & end with magic and the like
        self.clone()
    }
}

impl Protocol for Message {
    fn to_proto_bytes(self) -> Vec<u8> {
        self.data
    }
}





#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Block {
    Magic(Magic),
    Param(Param),
    Command(Command)
}



#[cfg(test)]
mod tests {
    use super::*;
    use assert_hex::assert_eq_hex;

    #[test]
    fn magic_works() {
        assert_eq!(&Magic::Start.to_proto_bytes(), &hex!("19B0A81D"));
        assert_eq!(&Magic::End.to_proto_bytes(), &hex!("EDA9F5CE"));
    }

    #[test]
    fn command_works() {
        assert_eq!(&Command::Init.to_proto_bytes(), &hex!("0002"));
        assert_eq!(&Command::Upload.to_proto_bytes(), &hex!("0006"));
        assert_eq!(&Command::Fin.to_proto_bytes(), &hex!("0007"));
    }

    #[test]
    fn message_builder() {
        let msg = Message::new()
            .append(Magic::Start)
            .append(Param::Cmd(Command::Init))
            .append(Param::Uuid(hex!("c2cd31ed27134010a0dedfc817a341b7")))
            .append(Magic::End)
            .build();
        assert_eq_hex!(
            &msg.to_proto_bytes(),
            &hex!("19b0a81d4d00000200024d080010c2cd31ed27134010a0dedfc817a341b7eda9f5ce")
        );
    }

    #[test]
    fn make_init_packet() {
        assert_eq_hex!(
            Message::make_init(hex!("c2cd31ed27134010a0dedfc817a341b7")).to_proto_bytes(),
            &hex!("19b0a81d4d00000200024d080010c2cd31ed27134010a0dedfc817a341b7eda9f5ce")
        );
    }
}
