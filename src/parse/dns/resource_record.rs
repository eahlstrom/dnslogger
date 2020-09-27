use crate::parse::dns::*;
use log::debug;
use nom::*;
use serde_derive::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

impl MxRecord {
    named!(parse_rdata<&[u8], (u16, CompressedNameChain)>, do_parse!(
        preference: be_u16 >>
        name_chain: parse_compressed_chain >>
        ((preference, name_chain))
    ));

    pub fn new(rr: &ResourceRecord, full_dns_message: &[u8]) -> MxRecord {
        let (_, (preference, mut name_chain)) = Self::parse_rdata(rr.rdata).unwrap();
        let exchange = match name_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_owned(),
            None => String::new(),
        };
        MxRecord {
            preference,
            exchange,
        }
    }
}

impl std::fmt::Display for MxRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}({})", self.exchange, self.preference)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ARecord {
    address: Ipv4Addr,
}

impl ARecord {
    named!(parse_rdata<&[u8], Ipv4Addr>, do_parse!(
        address: be_u32 >>
        (Ipv4Addr::from(address))
    ));

    pub fn new(rr: &ResourceRecord) -> ARecord {
        let (_, address) = Self::parse_rdata(rr.rdata).unwrap();
        ARecord { address }
    }
}

impl std::fmt::Display for ARecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AAAARecord {
    address: Ipv6Addr,
}

impl AAAARecord {
    named!(parse_rdata<&[u8], Ipv6Addr>, do_parse!(
        address: be_u128 >>
        (Ipv6Addr::from(address))
    ));

    pub fn new(rr: &ResourceRecord) -> AAAARecord {
        let (_, address) = Self::parse_rdata(rr.rdata).unwrap();
        AAAARecord { address }
    }
}

impl std::fmt::Display for AAAARecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PtrRecord {
    name: String,
}

impl PtrRecord {
    named!(parse_rdata<&[u8], CompressedNameChain>, do_parse!(
        name_chain: parse_compressed_chain >>
        (name_chain)
    ));

    pub fn new(rr: &ResourceRecord, full_dns_message: &[u8]) -> PtrRecord {
        let (_, mut name_chain) = Self::parse_rdata(rr.rdata).unwrap();
        let name = match name_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_string(),
            None => String::new(),
        };
        PtrRecord { name }
    }
}

impl std::fmt::Display for PtrRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TxtRecord {
    len: u8,
    bytes: Vec<u8>,
    text: String,
}

impl TxtRecord {
    named!(parse_rdata<&[u8], (u8, &[u8])>, do_parse!(
        len: be_u8 >>
        bytes: take!(len) >>
        ((len, bytes))
    ));

    pub fn new(rr: &ResourceRecord) -> TxtRecord {
        let (_, (len, bytes)) = Self::parse_rdata(rr.rdata).unwrap();
        TxtRecord {
            len,
            bytes: bytes.to_vec(),
            text: String::from_utf8_lossy(bytes).to_string(),
        }
    }
}

impl std::fmt::Display for TxtRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.text)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CNameRecord {
    name: String,
}

impl CNameRecord {
    named!(parse_rdata<&[u8], CompressedNameChain>, do_parse!(
        name_chain: parse_compressed_chain >>
        (name_chain)
    ));

    pub fn new(rr: &ResourceRecord, full_dns_message: &[u8]) -> CNameRecord {
        let (_, mut name_chain) = Self::parse_rdata(rr.rdata).unwrap();
        let name = match name_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_string(),
            None => String::new(),
        };
        CNameRecord { name }
    }
}

impl std::fmt::Display for CNameRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NsRecord {
    name: String,
}

impl NsRecord {
    named!(parse_rdata<&[u8], CompressedNameChain>, do_parse!(
        name_chain: parse_compressed_chain >>
        (name_chain)
    ));

    pub fn new(rr: &ResourceRecord, full_dns_message: &[u8]) -> NsRecord {
        let (_, mut name_chain) = Self::parse_rdata(rr.rdata).unwrap();
        let name = match name_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_owned(),
            None => String::new(),
        };
        NsRecord { name }
    }
}

impl std::fmt::Display for NsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SrvRecord {
    prio: u16,
    weight: u16,
    port: u16,
    target: String,
}

impl SrvRecord {
    named!(parse_rdata<&[u8], (u16, u16, u16, CompressedNameChain)>, do_parse!(
        prio: be_u16 >>
        weight: be_u16 >>
        port: be_u16 >>
        target_chain: parse_compressed_chain >>
        ((prio, weight, port, target_chain))
    ));

    pub fn new(rr: &ResourceRecord, full_dns_message: &[u8]) -> SrvRecord {
        let (_, (prio, weight, port, mut target_chain)) = Self::parse_rdata(rr.rdata).unwrap();
        let target = match target_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_string(),
            None => String::new(),
        };
        SrvRecord {
            prio,
            weight,
            port,
            target,
        }
    }
}

impl std::fmt::Display for SrvRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.prio, self.weight, self.port, self.target
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OptionCookie {
    client_cookie: String,
    server_cookie: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum EdnsOption {
    COOKIE(OptionCookie),
    UnknownCode(u16),
}

pub(crate) fn parse_edns_option(i: &[u8]) -> IResult<&[u8], EdnsOption> {
    let (i, code) = be_u16(i)?;
    let (i, len) = be_u16(i)?;
    let (i, data) = take!(i, len)?;

    match code {
        10 => {
            let client_cookie = hex::encode(&data[0..8]);
            let server_cookie = if data.len() >= 16 {
                hex::encode(&data[8..16])
            } else {
                String::from("<MISSING>")
            };
            value!(
                i,
                EdnsOption::COOKIE(OptionCookie {
                    client_cookie,
                    server_cookie,
                })
            )
        }
        _ => value!(i, EdnsOption::UnknownCode(code)),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OptRecord {
    udp_payload_size: u16,
    e_rcode: u8,
    version: u8,
    opt_do: u8,
    z: u16,
    options: Vec<EdnsOption>,
}

impl OptRecord {
    pub fn new(rr: &ResourceRecord, _full_dns_message: &[u8]) -> OptRecord {
        let udp_payload_size = match rr.rrclass {
            DnsClass::UnknownClass(udp_payload_size) => udp_payload_size,
            _ => 0,
        };
        let e_rcode = ((rr.ttl >> 24) & 0xff) as u8;
        let version = ((rr.ttl >> 16) & 0xff) as u8;
        let opt_do = ((rr.ttl >> 15) & 1) as u8;
        let z = (rr.ttl & 0x7fff) as u16;

        let mut options = Vec::new();
        let mut rest = rr.rdata;
        for _ in 0..20 {
            match parse_edns_option(rest) {
                Ok((r, option)) => {
                    options.push(option);
                    if r.is_empty() {
                        break;
                    }
                    rest = r;
                }
                Err(_) => {
                    break;
                }
            }
        }

        OptRecord {
            udp_payload_size,
            e_rcode,
            version,
            opt_do,
            z,
            options,
        }
    }
}

impl std::fmt::Display for OptRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<ROOT>")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SoaRecord {
    mname: String,
    rname: String,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
}

impl SoaRecord {
    named!(parse_rdata<&[u8], (CompressedNameChain, CompressedNameChain, u32, u32, u32, u32)>, do_parse!(
        mname: parse_compressed_chain >>
        rname: parse_compressed_chain >>
        serial: be_u32 >>
        refresh: be_u32 >>
        retry: be_u32 >>
        expire: be_u32 >>
        ((mname,rname,serial,refresh,retry, expire))
    ));

    pub fn new(rr: &ResourceRecord, full_dns_message: &[u8]) -> SoaRecord {
        let (_, (mut mname_chain, mut rname_chain, serial, refresh, retry, expire)) =
            Self::parse_rdata(rr.rdata).unwrap();
        let mname = match mname_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_string(),
            None => String::new(),
        };
        let rname = match rname_chain.resolve_name(0, full_dns_message) {
            Some(n) => n.to_string(),
            None => String::new(),
        };

        SoaRecord {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
        }
    }
}

impl std::fmt::Display for SoaRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}/{}",
            self.mname, self.serial, self.refresh, self.retry, self.expire
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RRecordTypes {
    MX(MxRecord),
    A(ARecord),
    AAAA(AAAARecord),
    PTR(PtrRecord),
    TXT(TxtRecord),
    CNAME(CNameRecord),
    NS(NsRecord),
    SRV(SrvRecord),
    SOA(SoaRecord),
    OPT(OptRecord),
    ParserNotImpl,
}

impl std::fmt::Display for RRecordTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RRecordTypes::MX(v) => write!(f, "{}", v),
            RRecordTypes::A(v) => write!(f, "{}", v),
            RRecordTypes::AAAA(v) => write!(f, "{}", v),
            RRecordTypes::PTR(v) => write!(f, "{}", v),
            RRecordTypes::TXT(v) => write!(f, "{}", v),
            RRecordTypes::CNAME(v) => write!(f, "{}", v),
            RRecordTypes::NS(v) => write!(f, "{}", v),
            RRecordTypes::SRV(v) => write!(f, "{}", v),
            RRecordTypes::SOA(v) => write!(f, "{}", v),
            RRecordTypes::OPT(v) => write!(f, "{}", v),
            RRecordTypes::ParserNotImpl => write!(f, "ParserNotImpl"),
            // _ => write!(f, "RRtodo()"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ResourceRecord<'a> {
    pub name_chain: CompressedNameChain<'a>,
    pub rrtype: DnsType,
    pub rrclass: DnsClass,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: &'a [u8],
    pub record: Option<RRecordTypes>,
}

impl<'a> ResourceRecord<'a> {
    pub fn resolve(&mut self, full_dns_message: &[u8]) {
        self.name_chain.resolve_name(0, full_dns_message);
        match self.record {
            Some(_) => {}
            None => match (&self.rrclass, &self.rrtype) {
                (DnsClass::IN, DnsType::MX) => {
                    self.record = Some(RRecordTypes::MX(MxRecord::new(self, full_dns_message)));
                }
                (DnsClass::IN, DnsType::A) => {
                    self.record = Some(RRecordTypes::A(ARecord::new(self)));
                }
                (DnsClass::IN, DnsType::AAAA) => {
                    self.record = Some(RRecordTypes::AAAA(AAAARecord::new(self)));
                }
                (DnsClass::IN, DnsType::PTR) => {
                    self.record = Some(RRecordTypes::PTR(PtrRecord::new(self, full_dns_message)));
                }
                (DnsClass::IN, DnsType::TXT) => {
                    self.record = Some(RRecordTypes::TXT(TxtRecord::new(self)));
                }
                (DnsClass::IN, DnsType::CNAME) => {
                    self.record = Some(RRecordTypes::CNAME(CNameRecord::new(
                        self,
                        full_dns_message,
                    )));
                }
                (DnsClass::IN, DnsType::NS) => {
                    self.record = Some(RRecordTypes::NS(NsRecord::new(self, full_dns_message)));
                }
                (DnsClass::IN, DnsType::SRV) => {
                    self.record = Some(RRecordTypes::SRV(SrvRecord::new(self, full_dns_message)));
                }
                (DnsClass::IN, DnsType::SOA) => {
                    self.record = Some(RRecordTypes::SOA(SoaRecord::new(self, full_dns_message)));
                }
                (DnsClass::UnknownClass(len), DnsType::OPT) => {
                    self.record = Some(RRecordTypes::OPT(OptRecord::new(
                        self,
                        full_dns_message,
                    )));
                    self.rrclass = DnsClass::OtherUsage(*len);
                }
                // (_, _) => self.record = Some(RRecordTypes::ParserNotImpl),
                (cc, tt) => {
                    self.record = Some(RRecordTypes::ParserNotImpl);
                    debug!(
                        "No parser for RRecord(DnsClass::{:?}, DnsType::{:?}) - rdata: {:02x?}",
                        cc, tt, self.rdata
                    );
                }
            },
        }
    }
}

#[rustfmt::skip]
named!(pub (crate) parse_resource_record<&[u8], ResourceRecord>, do_parse!(
    name_chain: parse_compressed_chain >>
    rrtype: parse_dnstype >> 
    rrclass: parse_dnsclass >>
    ttl: be_u32 >>
    rdlength: be_u16 >>
    rdata: take!(rdlength) >>
    (
        ResourceRecord{ name_chain, rrtype, rrclass, ttl, rdlength, rdata, record: None }
    )
));

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]

    const DNS_RESPONSE: &[u8] = include_bytes!("../../../fixtures/dns/dns_response1.bin");

    #[test]
    fn test_parse_resource_record() {
        let (offset, len) = (28, 22);
        let rr1 = &DNS_RESPONSE[offset..offset + len];
        let (_, rr) = parse_resource_record(rr1).unwrap();
        println!("{:?}", rr);
        assert_eq!(rr.rrtype, DnsType::MX);
        assert_eq!(rr.rrclass, DnsClass::IN);
    }

    #[test]
    fn test_mx_record_parser() {
        let rdata: [u8; 10] = [0, 40, 5, 115, 109, 116, 112, 52, 192, 12];
        let (_, v) = MxRecord::parse_rdata(&rdata).unwrap();
        println!("MxRecord::parse_rdata -> {:?}", v);
        assert!(true);
    }

    #[test]
    fn test_a_record_parser() {
        let rdata: [u8; 4] = [216, 239, 37, 26];
        let (_, v) = ARecord::parse_rdata(&rdata).unwrap();
        println!("ARecord::parse_rdata -> {:?}", v);
        assert_eq!(Ipv4Addr::new(216, 239, 37, 26), v);
    }

    #[test]
    fn test_aaaa_record_parser() {
        let rdata: [u8; 16] = [
            32, 1, 4, 248, 0, 4, 0, 7, 2, 224, 129, 255, 254, 82, 154, 107,
        ];
        let (_, v) = AAAARecord::parse_rdata(&rdata).unwrap();
        println!("AAAARecord::parse_rdata -> {:?}", v);
        // assert_eq!(Ipv4Addr::new(216, 239, 37, 26), v);
    }

    #[test]
    fn test_ptr_record_parser() {
        let rdata: [u8; 32] = [
            12, 54, 54, 45, 49, 57, 50, 45, 57, 45, 49, 48, 52, 3, 103, 101, 110, 9, 116, 119, 116,
            101, 108, 101, 99, 111, 109, 3, 110, 101, 116, 0,
        ];
        let (_, v) = PtrRecord::parse_rdata(&rdata).unwrap();
        println!("PtrRecord::parse_rdata -> {:?}", v);
    }

    #[test]
    fn test_txt_record_parser() {
        let rdata: [u8; 16] = [
            15, 118, 61, 115, 112, 102, 49, 32, 112, 116, 114, 32, 63, 97, 108, 108,
        ];
        let (_, (len, v)) = TxtRecord::parse_rdata(&rdata).unwrap();
        println!(
            "TxtRecord::parse_rdata -> len:{}, bytes: {:x?}, string: {:?}",
            len,
            v,
            String::from_utf8_lossy(v)
        );
    }

    #[test]
    fn test_cname_record_parser() {
        let rdata: [u8; 8] = [3, 119, 119, 119, 1, 108, 192, 16];
        let (_, v) = CNameRecord::parse_rdata(&rdata).unwrap();
        println!("CnameRecord::parse_rdata -> {:?}", v);
    }

    #[test]
    fn test_ns_record_parser() {
        let rdata: [u8; 14] = [
            6, 110, 115, 45, 101, 120, 116, 4, 110, 114, 116, 49, 192, 12,
        ];
        let (_, v) = NsRecord::parse_rdata(&rdata).unwrap();
        println!("NsRecord::parse_rdata -> {:?}", v);
    }

    #[test]
    fn test_srv_record_parser() {
        let rdata: [u8; 8] = [0, 0, 0, 0, 1, 189, 192, 12];
        let (_, v) = SrvRecord::parse_rdata(&rdata).unwrap();
        println!("SrvRecord::parse_rdata -> {:?}", v);
    }

    #[test]
    fn test_soa_record_parser() {
        let rdata: [u8; 38] = [
            3, 110, 115, 49, 192, 16, 9, 100, 110, 115, 45, 97, 100, 109, 105, 110, 192, 16, 13,
            158, 42, 169, 0, 0, 3, 132, 0, 0, 3, 132, 0, 0, 7, 8, 0, 0, 0, 60,
        ];
        let (_, v) = SoaRecord::parse_rdata(&rdata).unwrap();
        println!("SoaRecord::parse_rdata -> {:?}", v);
    }

    #[test]
    fn test_edns_option_parser() {
        let rdata: [u8; 12] = [
            0x00, 0x0a, 0x00, 0x08, 0x8e, 0xa0, 0xf3, 0xd3, 0x6b, 0x19, 0x5c, 0xf7,
        ];

        let (r, edns_option) = parse_edns_option(&rdata).unwrap();
        println!("{:?}", edns_option);
        assert!(r.len() == 0);
    }

    #[test]
    fn test_opt_record_parser() {
        let rdata: [u8; 23] = [
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00,
            0x08, 0x8e, 0xa0, 0xf3, 0xd3, 0x6b, 0x19, 0x5c, 0xf7,
        ];

        let (_, rr) = parse_resource_record(&rdata).unwrap();
        assert_eq!(rr.rrtype, DnsType::OPT);

        let v = OptRecord::new(&rr, &rdata);
        println!("{:#?}", v);
        assert_eq!(v.udp_payload_size, 4096);
    }

}
