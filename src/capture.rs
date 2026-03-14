use chrono::{DateTime, Local};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::{collections::VecDeque, time::Instant};

use crate::geo::GeoResolver;

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
    pub country_code: String,
}

pub struct GraphData {
    pub rx_history: VecDeque<u64>,
    pub tx_history: VecDeque<u64>,
    pub total_history: VecDeque<u64>,
    pub max_samples: usize,
}
impl GraphData {
    pub fn new(size: usize) -> Self {
        Self {
            rx_history: VecDeque::from(vec![0; size]),
            tx_history: VecDeque::from(vec![0; size]),
            total_history: VecDeque::from(vec![0; size]),
            max_samples: size,
        }
    }
    pub fn update(&mut self, rx: u64, tx: u64) {
        self.rx_history.push_back(rx);
        self.tx_history.push_back(tx);
        self.total_history.push_back(rx + tx);

        if self.rx_history.len() > self.max_samples {
            self.rx_history.pop_front();
            self.tx_history.pop_front();
            self.total_history.pop_front();
        }
    }
}
pub struct GlobalStats {
    pub graph: GraphData,
    pub total_rx: u64,
    pub total_tx: u64,
}
impl GlobalStats {
    pub fn new(size: usize) -> Self {
        Self {
            graph: GraphData::new(size),
            total_tx: 0,
            total_rx: 0,
        }
    }
    pub fn update(&mut self, rx: u64, tx: u64) {
        self.total_rx += rx;
        self.total_tx += tx;

        self.graph.update(rx, tx);
    }
}

pub fn parse_packet_full(
    data: &[u8],
    app_name: String,
    geo_resolver: &GeoResolver,
) -> Option<PacketData> {
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
                source = format!("{}:{}", source, tcp.source_port());
                dest = format!("{}:{}", dest, tcp.destination_port());
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
                source = format!("{}:{}", source, udp.source_port());
                dest = format!("{}:{}", dest, udp.destination_port());
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

    let src = source.clone();
    let dst = dest.clone();

    let remote_ip = if is_local_ip(&src) { &dst } else { &src };

    // Logic to strip port from IPv4 or IPv6
    let ip_only = if remote_ip.contains(']') {
        // Case: [2001:db8::1]:443 -> 2001:db8::1
        remote_ip
            .trim_start_matches('[')
            .split("]:")
            .next()
            .unwrap_or(remote_ip)
    } else if remote_ip.split(':').count() > 2 {
        // Case: 2001:db8::1 (IPv6 without brackets/port)
        remote_ip
    } else {
        // Case: 1.2.3.4:80 -> 1.2.3.4
        remote_ip.split(':').next().unwrap_or(remote_ip)
    };

    let country = geo_resolver.resolve(&ip_only);
    details.push_str(&format!("country code: {}\n", country));

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
        country_code: country,
    })
}
pub fn is_local_ip(ip: &str) -> bool {
    if ip.starts_with("127.")
        || ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || ip.starts_with("172.")
    {
        return true;
    }

    // IPv6 Checks
    let ip_low = ip.to_lowercase();
    if ip_low.contains("::1") ||       // Loopback
       ip_low.starts_with("fe80:") ||  // Link-local
       ip_low.starts_with("fc00:") ||  // Unique local
       ip_low.starts_with("fd00:")
    {
        // Unique local
        return true;
    }

    false
}
