use protocol::parse;
use std::io::{stdin, BufRead};

fn main() {
    stdin().lock().lines().flat_map(|x| x.ok()).for_each(|x| {
        match parse(&hex::decode(x).unwrap()) {
            Ok((_, params)) => {
                for i in params {
                    println!("{:x?}", i);
                }
            }
            Err(e) => {
                println!("{}", e);
            }
        }
        println!("\n");
    })
}
