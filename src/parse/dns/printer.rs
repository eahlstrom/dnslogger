use crate::parse::dns::*;
use log::debug;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    Packet,
};
use serde_derive::Serialize;
use serde_json::Error;

#[derive(Debug, PartialEq, Serialize)]
pub(crate) struct ResourceRecordPrinter {
    name: String,
    rrtype: String,
    rrclass: String,
    ttl: u32,
    rdata: RRecordTypes,
}

impl ResourceRecordPrinter {
    pub fn from_rr(rr: &ResourceRecord) -> ResourceRecordPrinter {
        let rrclass = match rr.rrclass {
            DnsClass::OtherUsage(_) => String::from("*"),
            _ => format!("{:?}", rr.rrclass),
        };

        let rrtype = format!("{:?}", rr.rrtype);
        let name: String = match &rr.name_chain.name {
            Some(name) => name.to_string(),
            None => String::new(),
        };

        let rdata = match rr.record.to_owned() {
            Some(record) => record,
            None => RRecordTypes::ParserNotImpl,
        };

        ResourceRecordPrinter {
            name,
            rrclass,
            rrtype,
            ttl: rr.ttl,
            rdata,
        }
    }
}

impl std::fmt::Display for ResourceRecordPrinter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}({})",
            self.rrclass, self.ttl, self.rrtype, self.name, self.rdata
        )
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub(crate) struct QueryPrinter {
    qclass: String,
    qtype: String,
    qname: String,
}

impl std::fmt::Display for QueryPrinter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.qclass, self.qtype, self.qname)
    }
}

impl QueryPrinter {
    pub fn from_query(q: &Query) -> QueryPrinter {
        let qclass = format!("{:?}", q.qclass);
        let qtype = format!("{:?}", q.qtype);
        let qname: String = match &q.name_chain.name {
            Some(name) => name.to_string(),
            None => String::new(),
        };
        QueryPrinter {
            qclass,
            qtype,
            qname,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub(crate) struct PrinterVec<T>(Vec<T>);

impl<D: std::fmt::Display> std::fmt::Display for PrinterVec<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let len = self.0.len();
        for (i, qp) in self.0.iter().enumerate() {
            write!(f, "{}", qp)?;
            if len > 1 && (i + 1) < len {
                write!(f, ", ")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct PacketPrinter {
    ts: String,
    proto: String,
    src: String,
    sport: u16,
    dest: String,
    dport: u16,
    qid: u16,
    opcode: String,
    qr: String,
    rcode: String,
    queries: PrinterVec<QueryPrinter>,
    answers: PrinterVec<ResourceRecordPrinter>,
    nsrecords: PrinterVec<ResourceRecordPrinter>,
    arecords: PrinterVec<ResourceRecordPrinter>,
}

impl PacketPrinter {
    pub fn new(
        packet: &pcap::Packet,
        ipv4: &Ipv4Packet,
        udp: &UdpPacket,
        dns: &DnsMessage,
    ) -> PacketPrinter {
        debug!("{:#?}", dns);
        let ts = format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
        let proto = String::from("UDP");
        let src = format!("{}", ipv4.get_source());
        let sport = udp.get_source();
        let dest = format!("{}", ipv4.get_destination());
        let dport = udp.get_destination();
        let qid = dns.header.id;
        let opcode = format!("{:?}", dns.header.flags.opcode);
        let qr = format!("{:?}", dns.header.flags.qr);
        let rcode = format!("{:?}", dns.header.flags.rcode);

        let mut queries: PrinterVec<QueryPrinter> = PrinterVec(Vec::new());
        for q in dns.queries.iter() {
            let qp = QueryPrinter::from_query(q);
            queries.0.push(qp);
        }

        let mut answers: PrinterVec<ResourceRecordPrinter> = PrinterVec(Vec::new());
        for rr in dns.answers.iter() {
            let rp = ResourceRecordPrinter::from_rr(rr);
            answers.0.push(rp);
        }

        let mut nsrecords: PrinterVec<ResourceRecordPrinter> = PrinterVec(Vec::new());
        for rr in dns.nsrecords.iter() {
            let rp = ResourceRecordPrinter::from_rr(rr);
            nsrecords.0.push(rp);
        }

        let mut arecords: PrinterVec<ResourceRecordPrinter> = PrinterVec(Vec::new());
        for rr in dns.arecords.iter() {
            let rp = ResourceRecordPrinter::from_rr(rr);
            arecords.0.push(rp);
        }

        PacketPrinter {
            ts,
            proto,
            src,
            sport,
            dest,
            dport,
            qid,
            opcode,
            qr,
            rcode,
            queries,
            answers,
            nsrecords,
            arecords,
        }
    }

    pub fn parse_packet(packet: &pcap::Packet) -> Option<PacketPrinter> {
        let ethernet = EthernetPacket::new(packet.data).unwrap();
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
                        let (_rest, dns_message) = dns_message(udp_packet.payload(), true).unwrap();
                        Some(PacketPrinter::new(
                            packet,
                            &ipv4_packet,
                            &udp_packet,
                            &dns_message,
                        ))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self)
    }
}

#[allow(clippy::format_in_format_args)]
impl std::fmt::Display for PacketPrinter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:18} {:3} {:>21} -> {:<21} {:6} {:>7}/{:<10} {:10}\t{}{}{}{}",
            self.ts,
            self.proto,
            format!("{}:{}", self.src, self.sport),
            format!("{}:{}", self.dest, self.dport),
            self.qid,
            self.opcode,
            self.qr,
            self.rcode,
            match self.queries.0.len() {
                0 => "".to_string(),
                _ => format!("{:<40}", format!("\tq:|{}|", self.queries)),
            },
            match self.answers.0.len() {
                0 => "".to_string(),
                _ => format!("\ta:|{}|", self.answers),
            },
            match self.nsrecords.0.len() {
                0 => "".to_string(),
                _ => format!("\tns:|{}|", self.nsrecords),
            },
            match self.arecords.0.len() {
                0 => "".to_string(),
                _ => format!("\tar:|{}|", self.arecords),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKTNO: usize = 1;
    const BPF: &str = "src port 53";

    #[test]
    fn test_print_text() {
        let mut cap = pcap::Capture::from_file("fixtures/dns/dns.pcap").unwrap();
        cap.filter(BPF).unwrap();
        for i in 1..PKTNO {
            cap.next().expect(&format!("failed to get packet {}!", i));
        }
        let pcap_pkt = cap.next().expect("failed to get packet!");
        if let Some(packet_printer) = PacketPrinter::parse_packet(&pcap_pkt) {
            println!("{}", packet_printer);
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_print_json() {
        let mut cap = pcap::Capture::from_file("fixtures/dns/dns.pcap").unwrap();
        cap.filter(BPF).unwrap();
        for i in 1..PKTNO {
            cap.next().expect(&format!("failed to get packet {}!", i));
        }
        let pcap_pkt = cap.next().expect("failed to get packet!");
        if let Some(packet_printer) = PacketPrinter::parse_packet(&pcap_pkt) {
            println!("{}", packet_printer.to_json().unwrap());
            assert!(true);
        } else {
            assert!(false);
        }
    }

}
