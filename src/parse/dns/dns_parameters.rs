use nom::*;
use serde_derive::Serialize;

#[derive(Clone, Debug, PartialEq)]
#[rustfmt::skip]
pub enum Qr {
    Query, Response,
}

#[derive(Clone, Debug, PartialEq)]
#[rustfmt::skip]
pub enum Opcode {
    Query, IQuery, Status, Reserved,
}

#[derive(Clone, Debug, PartialEq)]
#[rustfmt::skip]
pub enum Rcode {
    NoError, FormErr, ServFail, NXDomain,
    NotImp, Refused, YXDomain, XrrSet,
    NotAuth, NotZone, Other(u8),
}

#[derive(Debug, PartialEq)]
pub struct Flags {
    pub qr: Qr,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: Rcode,
}

pub(crate) fn parse_flags(i: &[u8]) -> IResult<&[u8], Flags> {
    let (i, flags) = be_u16(i)?;

    let qr = match (flags & 0x8000) >> 15 {
        0 => Qr::Query,
        1 => Qr::Response,
        _ => Qr::Query,
    };

    let opcode = match (flags & 0x7800) >> 11 {
        0 => Opcode::Query,
        1 => Opcode::IQuery,
        2 => Opcode::Status,
        _ => Opcode::Reserved,
    };

    let aa = (flags & 0x400) == 0x400;
    let tc = (flags & 0x200) == 0x200;
    let rd = (flags & 0x100) == 0x100;
    let ra = (flags & 0x80) == 0x80;

    let rcode = match flags & 0xf {
        0 => Rcode::NoError,
        1 => Rcode::FormErr,
        2 => Rcode::ServFail,
        3 => Rcode::NXDomain,
        4 => Rcode::NotImp,
        5 => Rcode::Refused,
        6 => Rcode::YXDomain,
        7 => Rcode::XrrSet,
        8 => Rcode::NotAuth,
        9 => Rcode::NotZone,
        _ => Rcode::Other((flags & 0xf) as u8),
    };

    #[rustfmt::skip]
    let flags = Flags { qr, opcode, aa, tc, rd, ra, rcode };

    value!(i, flags)
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[rustfmt::skip]
pub enum DnsType {
    A, NS, CNAME, SOA, WKS, PTR, HINFO, MX, TXT, AXFR, ALL,
    AAAA, LOC, SPF, SRV, TKEY, TSIG, IXFR, URI, TA, DLV,
    OPT, NSEC,
    UnknownType(u16),
}

#[rustfmt::skip]
named!(pub (crate) parse_dnstype<&[u8], DnsType>, do_parse!(
    qtype: be_u16 >>
    (match qtype {
            1   => DnsType::A,
            2   => DnsType::NS,
            5   => DnsType::CNAME,
            6   => DnsType::SOA,
            11  => DnsType::WKS,
            12  => DnsType::PTR,
            13  => DnsType::HINFO,
            15  => DnsType::MX,
            16  => DnsType::TXT,
            28  => DnsType::AAAA,
            29  => DnsType::LOC,
            33  => DnsType::SRV,
            41  => DnsType::OPT,
            47  => DnsType::NSEC,
            99  => DnsType::SPF,
            249 => DnsType::TKEY,
            250 => DnsType::TSIG,
            251 => DnsType::IXFR,
            252 => DnsType::AXFR,
            255 => DnsType::ALL,
            256 => DnsType::URI,
            32768 => DnsType::TA,
            32769 => DnsType::DLV,
            _   => DnsType::UnknownType(qtype),
    })
));

#[derive(Clone, Debug, PartialEq, Serialize)]
#[rustfmt::skip]
pub enum DnsClass {
    IN, CS, CH, HS, ALL, UnknownClass(u16),
}

#[rustfmt::skip]
named!(pub (crate) parse_dnsclass<&[u8], DnsClass>, do_parse!(
    qclass: be_u16 >>
    (match qclass & 32767 { // Clear the "UNICAST-RESPONSE" flag.
            1   => DnsClass::IN,
            2   => DnsClass::CS,
            3   => DnsClass::CH,
            4   => DnsClass::HS,
            255 => DnsClass::ALL,
            _   => DnsClass::UnknownClass(qclass),
    })
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flags() {
        let flag_data: [u8; 2] = [0x81, 0x80];
        let (_, flags) = parse_flags(&flag_data).unwrap();
        println!("{:?}", flags);

        assert_eq!(flags.qr, Qr::Response);
        assert_eq!(flags.opcode, Opcode::Query);
        assert_eq!(flags.rcode, Rcode::NoError);
        assert!(!flags.aa);
        assert!(flags.rd);
    }

    #[test]
    fn test_parse_dnsclass() {
        let data: [u8; 2] = [0, 255];
        let (_, x) = parse_dnsclass(&data).unwrap();
        assert_eq!(DnsClass::ALL, x);
    }

    #[test]
    fn test_parse_dnstype() {
        let data: [u8; 2] = [0, 33];
        let (_, x) = parse_dnstype(&data).unwrap();
        assert_eq!(DnsType::SRV, x);
    }

}
