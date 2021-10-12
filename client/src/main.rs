extern crate protocol;

use protocol::*;
use std::io::{BufRead, BufReader, Read, stdin, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use hex_literal::hex;
use thiserror::private::PathAsDisplay;
use ring::digest::{Context, Digest, SHA256};

const FINGERPRINT: &str = "dXNlcm5hbWU9c2t5,dmVyc2lvbj0yLjEuMy4wLVBRRg==,b3M9TGludXg=,dGltZXN0YW1wPTE2MzQwNTAwNTY=";
const KEY: &str = "sky+2.1.3.0+1634050056";
const SERVER_KEY: [u8; 32] = hex!("e8f1fbc853bdd630b7a2eda38c3100fcbe51227748ea9a6d73d5c18b846fb738");
const UUID: [u8; 16] = hex!("000102030405060708090a0b0c0d0f10");

pub fn htons(u: u16) -> u16 {
    u.to_be()
}

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

fn sha256_digest(data: &[u8]) -> Digest {
    let mut context = Context::new(&SHA256);
    context.update(data);
    context.finish()
}

fn length_header(length: u16) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf[0] = 0x12;
    buf[1] = 0x21; // haha random
    let size1 = ntohs(0x2112) as u32;
    let size2 = ((length as u32).wrapping_sub(size1)).wrapping_add(0x10000);
    let uvar2 = htons((size2 % 0xffff) as u16);
    buf[2] = (uvar2 & 0xff) as u8;
    buf[3] = ((uvar2 >> 8) & 0xff) as u8;
    buf
}

fn make_handshake() -> Vec<u8> {
    let (public, private) = sodiumoxide::crypto::box_::gen_keypair();
    let nonce = sodiumoxide::crypto::box_::gen_nonce();
    let server_public_key = sodiumoxide::crypto::box_::PublicKey::from_slice(&SERVER_KEY).unwrap();
    let mut output = Vec::new();
    output.extend(public.0.into_iter());
    output.extend(length_header(0x7f).into_iter());
    output.extend(nonce.0.into_iter());
    output.append(&mut sodiumoxide::crypto::box_::seal(FINGERPRINT.as_bytes(), &nonce, &server_public_key, &private));
    output
}


fn encrypt(message: Vec<u8>) -> Vec<u8> {
    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
    let key = sodiumoxide::crypto::secretbox::Key::from_slice(sha256_digest(KEY.as_bytes()).as_ref()).unwrap();
    let cipher = sodiumoxide::crypto::secretbox::seal(message.as_slice(), &nonce, &key);
    let mut output = Vec::new();
    output.extend(length_header(message.len() as u16 + 0x18).into_iter());
    output.extend(nonce.0.into_iter());
    output.extend(cipher.into_iter());
    output
}

fn decrypt(message: Vec<u8>) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};
    let digest = sha256_digest(KEY.as_bytes());
    let key = Key::from_slice(digest.as_ref()).expect("lmao invalid key");
    let nonce = Nonce::from_slice(&message[4..28]).expect("lmao invalid nonce");
    let cipher = &message[28..];
    sodiumoxide::crypto::secretbox::xsalsa20poly1305::open(cipher, &nonce, &key)
}

fn send_message(stream: &mut TcpStream, plaintext: Vec<u8>) -> Vec<Block> {
    stream.write(encrypt(plaintext).as_slice()).unwrap();
    let mut read = BufReader::new(stream.try_clone().unwrap());
    let mut response = Vec::new();
    let plaintext_response = loop {
        read.read(&mut response).unwrap();
        if let Ok(data) = decrypt(response.clone()) {
            break data;
        }
    };
    let (_, blocks) = parse(&response).unwrap();
    let mut log = std::fs::OpenOptions::new().write(true).append(true).open("message.log").unwrap();
    for i in blocks.iter() {
        writeln!(&mut log, "{:?}", i);
        writeln!(&mut log, "\n");
    }
    blocks
}

fn main() {
    let mut cwd = PathBuf::from("/");
    let mut stdin = stdin();
    let mut inp = stdin.lock();
    let mut stream = TcpStream::connect("127.0.0.1:6666").unwrap();
    stream.write(&make_handshake());
    send_message(&mut stream, Message::make_init(UUID.clone()).to_proto_bytes());
    loop {
        print!("> ");
        std::io::stdout().flush().unwrap();
        let (cmd, opt) = {
            let mut str = String::new();
            inp.read_line(&mut str);
            let mut trimmed = str.trim_end().to_string();
            let mut elems = trimmed.split(" ");
            (elems.next().unwrap().to_string(), elems.collect::<Vec<_>>().join(" "))
        };

        match cmd.as_str() {
            "cd" => {
                if opt == ".." {
                    cwd.pop();
                } else {
                    cwd.push(&opt);
                }
            }
            "pwd" => {
                println!("{}", cwd.as_display());
            }
            "ls" => {
                send_message(&mut stream, Message::make_list_dir(UUID.clone(), cwd.as_path()).to_proto_bytes())
                    .into_iter()
                    .filter_map(|x| match x {
                        Block::Param(Param::FolderContents(contents)) => Some(contents),
                        _ => None
                    }).for_each(|x| println!("{:?}", x));
            }
            "get" => {
                if opt.len() != 0 {
                    let mut f = std::fs::OpenOptions::new().write(true).append(true).open(&format!("received/{}", &opt)).unwrap();
                    send_message(&mut stream, Message::make_read_file(UUID.clone(), cwd.as_path(), &opt).to_proto_bytes())
                        .into_iter()
                        .filter_map(|x| match x {
                            Block::Param(Param::Contents(contents)) => Some(contents),
                            _ => None
                        }).for_each(|x| { f.write(&x); });
                } else {
                    println!("lol you need an arg")
                }
            }
            _ => {
                println!("unsupported command :(");
            }
        }

        println!("{:?}, {:?}", cmd, opt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_header() {
        assert_eq!(length_header(0x7f), hex!("1221ee5e"))
    }

    #[test]
    fn test_handshake_len() {
        let handshake = make_handshake();
        assert_eq!(handshake.len(), 163);
        assert_eq!(&handshake[32..36], &hex!("1221ee5e"));
    }

    #[test]
    fn test_encrypt_len() {
        assert_eq!(encrypt(Message::make_init(UUID.clone()).to_proto_bytes()).len(), 78);
    }
}