use nom::{
    bytes::complete::{tag, take_while_m_n},
    combinator::map_res,
    sequence::tuple,
    IResult,
};

use crate::protocol::*;
use byteorder::{BigEndian, ReadBytesExt};
use hex_literal::hex;
use nom::bytes::complete::take;
use num_traits::{FromPrimitive, ToPrimitive};

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

fn match_param_string(input: &[u8], param: [u8; 2]) -> IResult<&[u8], Block> {
    let (input, _) = tag(param)(input)?;
    let (input, size) = take(2usize)(input)?; // ALWAYS 2?
    let size = (((size[0] as u16) << 8u16) | size[1] as u16) as usize;
    let (input, str) = take(size)(input)?;
    let mut str = String::from_utf8_lossy(&str[..str.len() - 1]).to_string();
    Ok((
        input,
        Block::Param(match param {
            hex!("4D14") => Param::DirName(str),
            hex!("4D1C") => Param::FileName(str),
            hex!("4D20") => Param::Contents(str),
            hex!("4D24") => Param::More(str),
            _ => panic!("um dont do that lol"),
        }),
    ))
}

fn match_param_dirname(input: &[u8]) -> IResult<&[u8], Block> {
    match_param_string(input, hex!("4D14"))
}

fn match_param_filename(input: &[u8]) -> IResult<&[u8], Block> {
    match_param_string(input, hex!("4D1C"))
}

fn match_param_contents(input: &[u8]) -> IResult<&[u8], Block> {
    match_param_string(input, hex!("4D20"))
}

fn match_param_more(input: &[u8]) -> IResult<&[u8], Block> {
    match_param_string(input, hex!("4D24"))
}

fn match_param_uuid(input: &[u8]) -> IResult<&[u8], Block> {
    let (input, _) = tag(hex!("4D08"))(input)?;
    let (input, _) = take(2usize)(input)?; // ALWAYS 2?
    let (input, uuid) = take(16usize)(input)?;
    let mut uuid_sized = [0u8; 16];
    uuid_sized.copy_from_slice(uuid);
    Ok((input, Block::Param(Param::Uuid(uuid_sized))))
}

fn match_param_code(input: &[u8]) -> IResult<&[u8], Block> {
    let (input, _) = tag(hex!("4D28"))(input)?;
    let (input, _) = take(2usize)(input)?; // ALWAYS 2?
    let (input, mut response) = take(4usize)(input)?;
    Ok((
        input,
        Block::Param(Param::Code(response.read_u32::<BigEndian>().unwrap())),
    ))
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

    #[test]
    fn test_match_commands() {
        assert_eq!(
            match_param_command(&hex!("4D0000020002")).unwrap().1,
            Block::Param(Param::Cmd(Command::Init))
        );
        assert_eq!(
            match_param_command(&hex!("4D0000020003")).unwrap().1,
            Block::Param(Param::Cmd(Command::GetSessionFolder))
        );
        assert_eq!(
            match_param_command(&hex!("4D0000020004")).unwrap().1,
            Block::Param(Param::Cmd(Command::ListDir))
        );
        assert_eq!(
            match_param_command(&hex!("4D0000020005")).unwrap().1,
            Block::Param(Param::Cmd(Command::ReadFile))
        );
        assert_eq!(
            match_param_command(&hex!("4D0000020006")).unwrap().1,
            Block::Param(Param::Cmd(Command::Upload))
        );
        assert_eq!(
            match_param_command(&hex!("4D0000020007")).unwrap().1,
            Block::Param(Param::Cmd(Command::Fin))
        );
    }

    #[test]
    fn test_match_param() {
        assert_eq!(
            match_param_uuid(&hex!("4D080010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
                .unwrap()
                .1,
            Block::Param(Param::Uuid(hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")))
        );

        assert_eq!(
            match_param_string(&hex!("4D1400084141414141414100"), hex!("4D14"))
                .unwrap()
                .1,
            Block::Param(Param::DirName("AAAAAAA".to_string()))
        );

        assert_eq!(
            match_param_dirname(&hex!("4D1400084141414141414100"))
                .unwrap()
                .1,
            Block::Param(Param::DirName("AAAAAAA".to_string()))
        );

        assert_eq!(
            match_param_filename(&hex!("4D1C00084141414141414100"))
                .unwrap()
                .1,
            Block::Param(Param::FileName("AAAAAAA".to_string()))
        );

        assert_eq!(
            match_param_contents(&hex!("4D2000084141414141414100"))
                .unwrap()
                .1,
            Block::Param(Param::Contents("AAAAAAA".to_string()))
        );

        assert_eq!(
            match_param_more(&hex!("4D2400084141414141414100"))
                .unwrap()
                .1,
            Block::Param(Param::More("AAAAAAA".to_string()))
        );

        assert_eq!(
            match_param_code(&hex!("4D28000400000009")).unwrap().1,
            Block::Param(Param::Code(9))
        );
    }
}
