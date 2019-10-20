# dnslogger
Passive dns sniffer. Provides dnslogger binary and a dns parser library.

## Install

Before installing make sure you have: libpcap-dev

<pre>
cargo install dnslogger
</pre>
_or_
<pre>
cargo build --release && cargo install --path .
</pre>

## Usage
<pre>
$ dnslogger --help
dnslogger 0.1.0
Erik Ahlström <ea@negahok.se>
Passive dns sniffer. Provides dnslogger binary and a dns parser library.

USAGE:
    dnslogger [FLAGS] [OPTIONS] [bpf_expression]

FLAGS:
    -h, --help       Prints help information
    -v, --verbose    Verbose mode (-v, -vv, -vvv, etc.)
    -V, --version    Prints version information

OPTIONS:
    -i <interface>            Listen on interface
    -o <output_format>        Set output format [default: Text]  [possible values: Text, Json]
    -r <pcap_file>            Read captured packets from pcap file

ARGS:
    <bpf_expression>    Set capture filter [default: src port (53 or 5353 or 5355)]
</pre>

<pre>
$ dnslogger -r fixtures/dns/dns.pcap 
1112172466.496576  UDP     192.168.170.20:53 -> 192.168.170.8:32795     4146   Query/Response   NoError   		q:|IN/TXT/google.com|                  	a:|IN/270/TXT/google.com("v=spf1 ptr ?all")|
...
</pre>

<pre>
$ dnslogger -r fixtures/dns/dns.pcap -o json
{"ts":"1112172466.496576","proto":"UDP","src":"192.168.170.20","sport":53,"dest":"192.168.170.8","dport":32795,"qid":4146,"opcode":"Query","qr":"Response","rcode":"NoError","queries":[{"qclass":"IN","qtype":"TXT","qname":"google.com"}],"answers":[{"name":"google.com","rrtype":"TXT","rrclass":"IN","ttl":270,"rdata":{"TXT":{"len":15,"bytes":[118,61,115,112,102,49,32,112,116,114,32,63,97,108,108],"text":"v=spf1 ptr ?all"}}}],"nsrecords":[],"arecords":[]}
</pre>
