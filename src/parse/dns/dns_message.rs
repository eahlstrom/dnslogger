use crate::parse::dns::*;
use nom::*;

#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: Flags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[rustfmt::skip]
named!(parse_dns_header<&[u8], DnsHeader>, do_parse!(
    id: be_u16 >>
    flags: parse_flags >>
    qdcount: be_u16 >>
    ancount: be_u16 >>
    nscount: be_u16 >>
    arcount: be_u16 >>
    (
        DnsHeader{id, flags, qdcount, ancount, nscount, arcount}
    )
));

#[derive(Debug, PartialEq)]
pub struct DnsMessage<'a> {
    pub header: DnsHeader,
    pub queries: Vec<Query<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub nsrecords: Vec<ResourceRecord<'a>>,
    pub arecords: Vec<ResourceRecord<'a>>,
}

#[rustfmt::skip]
named!(parse_dns_message<&[u8], DnsMessage>, do_parse!(
    header: parse_dns_header >>
    queries: count!(parse_query, header.qdcount as usize) >>
    answers: count!(parse_resource_record, header.ancount as usize) >>
    nsrecords: count!(parse_resource_record, header.nscount as usize) >>
    arecords: count!(parse_resource_record, header.arcount as usize) >>
    (
        DnsMessage{header, queries, answers, nsrecords, arecords}
    )
));

pub fn dns_message(data: &[u8], resolve_resource_records: bool) -> IResult<&[u8], DnsMessage> {
    let (rest, mut dns_message) = parse_dns_message(data).unwrap();

    for q in dns_message.queries.iter_mut() {
        q.name_chain.resolve_name(0, data);
    }

    if resolve_resource_records {
        for rr in dns_message.answers.iter_mut() {
            rr.resolve(data);
        }

        for rr in dns_message.nsrecords.iter_mut() {
            rr.resolve(data);
        }

        for rr in dns_message.arecords.iter_mut() {
            rr.resolve(data);
        }
    }
    value!(rest, dns_message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS_RESPONSE: &[u8] = include_bytes!("../../../fixtures/dns/dns_response1.bin");

    #[test]
    fn test_parse_dns_message() {
        let (_res, mut dns_message) = parse_dns_message(&DNS_RESPONSE).unwrap();
        println!("{:?}", dns_message);
        assert_eq!(dns_message.header.id, 63343);
        assert_eq!(dns_message.header.qdcount, 1);
        assert_eq!(dns_message.header.ancount, 6);
        assert_eq!(dns_message.header.nscount, 0);
        assert_eq!(dns_message.header.arcount, 6);

        println!("--");
        println!("Queries:");
        for (i, anrr) in dns_message.queries.iter_mut().enumerate() {
            anrr.name_chain.resolve_name(0, &DNS_RESPONSE);
            println!("  {}: {:?}", i, anrr);
        }

        println!("Answers:");
        for (i, anrr) in dns_message.answers.iter_mut().enumerate() {
            anrr.resolve(&DNS_RESPONSE);
            println!("  {}: {:?}", i, anrr);
        }

        println!("Additional records:");
        for (i, anrr) in dns_message.arecords.iter_mut().enumerate() {
            anrr.resolve(&DNS_RESPONSE);
            println!("  {}: {:?}", i, anrr);
        }
    }

    #[test]
    fn test_dns_message() {
        let (_rest, dns_message) = dns_message(&DNS_RESPONSE, true).unwrap();
        println!("{:#x?}", dns_message);
        assert_eq!(dns_message.header.arcount, 6);
        let should_be = Some("smtp3.google.com".to_string());
        assert_eq!(should_be, dns_message.arecords[5].name_chain.name);
    }

    #[test]
    fn test_should_handle_looping_pointers() {
        #[allow(unused_variables)]
        let dns_data: &[u8] = include_bytes!("../../../fixtures/dns/dns_looping_pointer.bin");
        let (_rest, dns_message) = dns_message(dns_data, false).unwrap();
        println!("{:?}", dns_message);
        assert!(true);
    }

}
