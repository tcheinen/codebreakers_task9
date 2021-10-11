#![feature(arbitrary_enum_discriminant)]


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
