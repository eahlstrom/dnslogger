use crate::parse::dns::*;
use nom::*;

#[derive(Debug, PartialEq, Eq)]
pub struct Query<'a> {
    pub name_chain: CompressedNameChain<'a>,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

#[rustfmt::skip]
named!(pub (crate) parse_query<&[u8], Query>, do_parse!(
    name_chain: parse_compressed_chain >>
    qtype: parse_dnstype >>
    qclass: parse_dnsclass >>
    (Query{name_chain, qtype, qclass})
));

#[cfg(test)]
mod tests {
    use super::*;

    const DNS_RESPONSE: &[u8] = include_bytes!("../../../fixtures/dns/dns_response1.bin");

    #[test]
    fn test_parse_query() {
        let (offset, len) = (12, 16);
        let query = &DNS_RESPONSE[offset..offset + len];
        let (_rest, query) = parse_query(query).unwrap();
        println!("{:?}", query);
        assert_eq!(query.qtype, DnsType::MX);
        assert_eq!(query.qclass, DnsClass::IN);
    }

}
