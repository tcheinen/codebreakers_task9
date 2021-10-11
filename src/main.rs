#![feature(arbitrary_enum_discriminant)]
extern crate serde;
extern crate alloc;
extern crate nom;

mod protocol;
mod error;
mod parser;

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;


}
