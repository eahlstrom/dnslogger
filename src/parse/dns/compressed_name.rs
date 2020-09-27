use log::error;
use nom::*;

const RESOLVE_NAME_RECURSION_MAX: usize = 10;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct CompressedNameChain<'a> {
    pub name: Option<String>,
    tokens: Vec<CompressedName<'a>>,
}

impl<'a> CompressedNameChain<'a> {
    pub fn push(&mut self, val: CompressedName<'a>) {
        self.tokens.push(val);
    }

    pub fn resolve_name(&mut self, recursion: usize, full_dns_message: &[u8]) -> &Option<String> {
        if recursion >= RESOLVE_NAME_RECURSION_MAX {
            error!("recursion exceeded!");
            return &None;
        }
        let recursion = recursion + 1;
        match &self.name {
            None => {
                let mut values: Vec<String> = Vec::new();
                for token in self.tokens.iter() {
                    match token {
                        CompressedName::Label(name) => values.push((*name).to_string()),
                        CompressedName::Pointer(offs) => {
                            let offs = *offs as usize;
                            if let Ok((_, mut name_chain)) =
                                parse_compressed_chain(&full_dns_message[offs..])
                            {
                                if let Some(full_name) =
                                    name_chain.resolve_name(recursion, full_dns_message)
                                {
                                    values.push(full_name.to_string());
                                }
                            } else {
                                error!("failed to parse_qname_chain: offs: {}", offs);
                            }
                        }
                    }
                }
                self.name = Some(values.join("."));
                &self.name
            }
            Some(_name) => &self.name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum CompressedName<'a> {
    Label(&'a str),
    Pointer(u16),
}

#[rustfmt::skip]
fn parse_compressed_token(i: &[u8]) -> IResult<&[u8], Option<CompressedName>> {
    let (i, len) = be_u8(i)?;
    let tt = (len & 0xc0) >> 6;
    let len = len & 0x3f;
    match tt {
        0b00 => match len {
            0 => Ok((i, None)),
            _ => do_parse!(i,
                    name: map_res!(take!(len), std::str::from_utf8) >>
                    (Some(CompressedName::Label(name)))
                 ),
        },
        0b11 => {
            let (i, len2) = be_u8(i)?;
            let offs = u16::from(len) << 8;
            let offs = offs | u16::from(len2);
            value!(i, Some(CompressedName::Pointer(offs)))
        }
        _ => {
            error!("invalid type byte found! 0b{:b}", tt);
            value!(i, None)
        }
    }
}

pub(crate) fn parse_compressed_chain(i: &[u8]) -> IResult<&[u8], CompressedNameChain> {
    let mut names = CompressedNameChain::default();
    if i[0] == 0u8 {
        let (i, _) = take!(i, 1).unwrap();
        names.name = Some(String::from("<ROOT>"));
        value!(i, names)
    } else {
        let mut rest = i;
        for _ in 0..100 {
            let (i, name) = parse_compressed_token(rest)?;
            rest = i;
            match name {
                Some(value) => {
                    names.push(value);
                    if let CompressedName::Pointer(_) = value {
                        break;
                    }
                }
                None => break,
            }
        }
        value!(rest, names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS_RESPONSE: &[u8] = include_bytes!("../../../fixtures/dns/dns_response1.bin");

    #[test]
    fn test_parse_compressed_token() {
        let data: [u8; 12] = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];
        let (_rest, name) = parse_compressed_token(&data).unwrap();
        assert_eq!(Some(CompressedName::Label("google")), name)
    }

    #[test]
    fn test_compressed_name_chain() {
        let mut cn = CompressedNameChain::default();
        let l1 = String::from("host");
        let l2 = String::from("subdomain");
        cn.push(CompressedName::Label(&l1));
        cn.push(CompressedName::Label(&l2));
        cn.push(CompressedName::Pointer(12));

        let name = cn.resolve_name(0, &DNS_RESPONSE);
        let should_be = &Some("host.subdomain.google.com".to_string());
        assert_eq!(should_be, name);
    }

    #[test]
    fn test_parse_compressed_chain() {
        let data: [u8; 12] = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        let (rest, mut nc) = parse_compressed_chain(&data).unwrap();
        println!("{:?}", nc);
        let name = nc.resolve_name(0, &DNS_RESPONSE);
        let should_be: &Option<String> = &Some("google.com".to_string());
        assert_eq!(should_be, name);
        assert_eq!(0, rest.len(), "should eat nullbyte at end");
    }

}
