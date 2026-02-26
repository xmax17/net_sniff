use chrono::{DateTime, Local};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::time::Instant;

pub struct PacketData {
    pub summary: String,
    pub timestamp: Instant, // For the Spike Inspector math
    pub time_label: String, // For the UI display (HH:MM:SS)   pub summary: String,
    pub full_details: String,
    pub hex_dump: String,
    pub app_name: String,
    pub source: String,
    pub dest: String,
    pub proto_label: String,
    pub length: usize,
}

pub fn parse_packet_full(data: &[u8], app_name: String) -> Option<PacketData> {
    let value = SlicedPacket::from_ethernet(data).ok()?;

    let mut source = String::from("Unknown");
    let mut dest = String::from("Unknown");
    let mut proto_label = String::from("DATA");
    let mut details = String::new();

    // --- NETWORK LAYER ---
    if let Some(net) = &value.net {
        details.push_str("--- NETWORK LAYER ---\n");
        match net {
            NetSlice::Ipv4(ipv4) => {
                source = format!("{}", ipv4.header().source_addr());
                dest = format!("{}", ipv4.header().destination_addr());
                details.push_str(&format!(
                    "Protocol: IPv4\nSource:   {}\nDest:     {}\nTTL:      {}\n",
                    source,
                    dest,
                    ipv4.header().ttl()
                ));
            }
            NetSlice::Ipv6(ipv6) => {
                source = format!("{:?}", ipv6.header().source_addr());
                dest = format!("{:?}", ipv6.header().destination_addr());
                details.push_str(&format!(
                    "Protocol: IPv6\nSource:   {}\nDest:     {}\n",
                    source, dest
                ));
            }
            // FIX: Handling ARP Packets
            NetSlice::Arp(arp) => {
                proto_label = "ARP".into();
                source = format!("{:X?}", arp.sender_hw_addr());
                dest = format!("{:X?}", arp.target_hw_addr());
                details.push_str(&format!(
                    "Protocol: ARP (Address Resolution)\nSender MAC: {:X?}\nTarget MAC: {:X?}\n",
                    arp.sender_hw_addr(),
                    arp.target_hw_addr()
                ));
            }
        }
    }

    // --- TRANSPORT LAYER ---
    if let Some(transport) = &value.transport {
        details.push_str("\n--- TRANSPORT LAYER ---\n");
        match transport {
            TransportSlice::Tcp(tcp) => {
                let port = tcp.destination_port();
                proto_label = match port {
                    80 => "HTTP".into(),
                    443 => "HTTPS".into(),
                    _ => format!("TCP:{}", port),
                };
                details.push_str(&format!(
                    "Type:  TCP\nPorts: {} -> {}\nSeq:   {}\nAck:   {}\n",
                    tcp.source_port(),
                    tcp.destination_port(),
                    tcp.sequence_number(),
                    tcp.acknowledgment_number()
                ));
            }
            TransportSlice::Udp(udp) => {
                proto_label = format!("UDP:{}", udp.destination_port());
                details.push_str(&format!(
                    "Type:  UDP\nPorts: {} -> {}\nLen:   {}\n",
                    udp.source_port(),
                    udp.destination_port(),
                    udp.length()
                ));
            }
            // FIX: Handling ICMP (Ping)
            TransportSlice::Icmpv4(icmp) => {
                proto_label = "ICMPv4".into();
                details.push_str(&format!(
                    "Type:  ICMPv4\nCode:  {:?}\n",
                    icmp.header().icmp_type
                ));
            }
            TransportSlice::Icmpv6(icmp) => {
                proto_label = "ICMPv6".into();
                details.push_str(&format!(
                    "Type:  ICMPv6\nCode:  {:?}\n",
                    icmp.header().icmp_type
                ));
            }
        }
    }

    let summary = format!("{:<15} -> {:<15} | {:^10}", source, dest, proto_label);

    let hex_dump = data
        .chunks(16)
        .map(|chunk| {
            let hex = chunk
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                .collect();
            format!("{:<48} | {}", hex, ascii)
        })
        .collect::<Vec<_>>()
        .join("\n");

    let length = data.len();

    Some(PacketData {
        timestamp: Instant::now(),
        time_label: Local::now().format("%H:%M:%S").to_string(),
        summary,
        full_details: details,
        hex_dump,
        app_name,
        source,
        dest,
        proto_label,
        length,
    })
}
