use nom::{
    IResult,
    bytes::complete::{tag, take_while_m_n},
    combinator::map_res,
    sequence::tuple
};
use crate::protocol::{*};
use hex_literal::hex;
use nom::bytes::complete::take;

fn match_end_magic(input: &[u8]) -> IResult<&[u8], Block> {
    let (input, _) = tag(Magic::End.to_proto_bytes().as_slice())(input)?;
    Ok((input, Block::Magic(Magic::End)))
}

fn match_param_command(input: &[u8]) -> IResult<&[u8], Block> {
    let (input, _) = tag(hex!("4D00"))(input)?;
    let (input, _) = take(2usize)(input)?; // ALWAYS 2?
    let (input, cmd) = take(2usize)(input)?;
    let cmd = Command::from_u16(((cmd[0] as u16) << 8u16) | cmd[1] as u16);
    Ok((input, Block::Param(Param::Cmd(cmd))))
}

fn parse(input: &[u8]) -> IResult<&[u8], Vec<Block>> {
    let mut output = Vec::new();
    let (input, _) = tag(Magic::Start.to_proto_bytes().as_slice())(input)?;
    output.push(Block::Magic(Magic::Start));
    Ok((input, output))
}

#[cfg(test)]
mod tests {
    use super::*;
}