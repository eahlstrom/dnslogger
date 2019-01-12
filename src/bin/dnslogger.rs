use clap::{_clap_count_exprs, arg_enum};
use dnslogger::parse::dns::PacketPrinter;
use log::{debug, info};
use pcap::Capture;
use std::env;
use structopt::StructOpt;

arg_enum! {
    #[derive(Debug)]
    enum OutputFormat {
        Text,
        Json,
    }
}

#[derive(Debug, StructOpt)]
#[structopt()]
pub struct Options {
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    loglevel: u8,

    /// Read captured packets from pcap file
    #[structopt(short = "r")]
    pcap_file: Option<String>,

    /// Listen on interface
    #[structopt(short = "i")]
    interface: Option<String>,

    /// Set output format
    #[structopt(
        short = "-o",
        default_value = "Text",
        raw(
            possible_values = "&OutputFormat::variants()",
            case_insensitive = "true"
        )
    )]
    output_format: OutputFormat,

    /// Set capture filter
    #[structopt(default_value = "src port (53 or 5353 or 5355)")]
    bpf_expression: String,
}

fn setup_logging(loglevel: u8) {
    match env::var("RUST_LOG") {
        Ok(_) => {}
        Err(_e) => {
            let loglevel = match loglevel {
                0 => "",
                1 => "dnslogger=info",
                2 => "dnslogger=debug",
                3 => "dnslogger=debug,parse=debug",
                _ => "debug",
            };
            if loglevel != "" {
                env::set_var("RUST_LOG", loglevel);
            }
        }
    };
    env_logger::init();
}

fn handle_packet(packet: &pcap::Packet, output_format: &OutputFormat) {
    if let Some(packet_printer) = PacketPrinter::parse_packet(&packet) {
        debug!("{:#?}", packet_printer);
        match output_format {
            OutputFormat::Text => println!("{}", packet_printer),
            OutputFormat::Json => println!("{}", packet_printer.to_json().unwrap()),
        }
    }
}

fn main() {
    let opts = Options::from_args();
    setup_logging(opts.loglevel);
    debug!("{:?}", opts);

    if let Some(pcap_file) = opts.pcap_file {
        info!("using pcap file {}", pcap_file);
        let mut cap = Capture::from_file(pcap_file).unwrap();
        cap.filter(&opts.bpf_expression[..]).unwrap();
        while let Ok(packet) = cap.next() {
            handle_packet(&packet, &opts.output_format);
        }
    } else if let Some(interface) = opts.interface {
        info!("using interface {}", interface);
        let mut cap = Capture::from_device(&interface[..])
            .unwrap()
            .promisc(true)
            .snaplen(0)
            .open()
            .unwrap();
        cap.filter(&opts.bpf_expression[..]).unwrap();
        while let Ok(packet) = cap.next() {
            handle_packet(&packet, &opts.output_format);
        }
    } else {
        eprintln!("Need an interface or a file. Se --help");
    }
}
