//! `dnslogger` passive dns logger.
//!
//!
//!     use pcap::{Capture, PacketHeader};
//!     use pnet::packet::{
//!         ethernet::{EtherTypes, EthernetPacket},
//!         ip::IpNextHeaderProtocols,
//!         ipv4::Ipv4Packet,
//!         udp::UdpPacket,
//!         Packet,
//!     };
//!
//!     pub fn handle_packet(packet: &pcap::Packet) {
//!         let ethernet = EthernetPacket::new(packet.data).unwrap();
//!         let resolve_all_resource_records = true;
//!         match ethernet.get_ethertype() {
//!             EtherTypes::Ipv4 => {
//!                 let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
//!                 if let IpNextHeaderProtocols::Udp = ipv4_packet.get_next_level_protocol() {
//!                     let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
//!                     let (rest, dns_message) = dnslogger::parse::dns_message(
//!                         udp_packet.payload(),
//!                         resolve_all_resource_records
//!                     ).unwrap();
//!                     println!("{:?}", dns_message);
//!                     println!("{:02x?}", rest);
//!                 }
//!             }
//!             _ => println!("unhandled packet: {:?}", ethernet),
//!         }
//!     }

pub mod parse;
