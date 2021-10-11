mod parser;
mod protocol;
mod error;

use crate::parser::parse;

fn main() {

    match parse(&hex::decode(std::env::args().nth(1).unwrap()).unwrap()) {
        Ok((_, params)) => {
            for i in params {
                println!("{:x?}", i);
            }
        },
        Err(e) => {
            println!("{}", e);
        }
    }
}