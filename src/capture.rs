use etherparse::SlicedPacket;

pub struct PacketData {
    pub summary: String,       
    pub full_details: String,  
    pub hex_dump: String,      
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    bytes.chunks(16)
        .map(|chunk| {
            chunk.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_protocol_info(data: &[u8]) -> String {
    let mut details = format!("--- PACKET METADATA ---\nSize: {} bytes\n", data.len());
    
    if let Ok(value) = SlicedPacket::from_ethernet(data) {
        // 1. Link Layer (MAC Addresses)
        if let Some(link) = &value.link {
            details.push_str("\n--- LINK LAYER ---\n");
            match link {
                etherparse::LinkSlice::Ethernet2(eth) => {
                    details.push_str(&format!(
                        "Src MAC: {:02X?}\nDst MAC: {:02X?}\n", 
                        eth.source(), 
                        eth.destination()
                    ));
                }
                _ => details.push_str("Link Type: Non-Ethernet\n"),
            }
        }

        // 2. Network Layer (IP Info)
        if let Some(net) = &value.net {
            details.push_str("\n--- NETWORK LAYER ---\n");
            match net {
                etherparse::NetSlice::Ipv4(ipv4) => {
                    details.push_str(&format!(
                        "Protocol: IPv4\nTTL: {}\nID: {}\n", 
                        ipv4.header().ttl(),
                        ipv4.header().identification()
                    ));
                }
                etherparse::NetSlice::Ipv6(ipv6) => {
                    details.push_str(&format!(
                        "Protocol: IPv6\nHop Limit: {}\n", 
                        ipv6.header().hop_limit()
                    ));
                }
                _ => details.push_str("Protocol: Other\n"),
            }
        }

        // 3. Transport Layer (TCP/UDP Details)
        if let Some(transport) = &value.transport {
            details.push_str("\n--- TRANSPORT LAYER ---\n");
            match transport {
                etherparse::TransportSlice::Tcp(tcp) => {
                    details.push_str(&format!(
                        "Type: TCP\nSrc Port: {}\nDst Port: {}\nWindow: {}\nSeq: {}\n",
                        tcp.source_port(), 
                        tcp.destination_port(), 
                        tcp.window_size(),
                        tcp.sequence_number()
                    ));
                }
                etherparse::TransportSlice::Udp(udp) => {
                    details.push_str(&format!(
                        "Type: UDP\nSrc Port: {}\nDst Port: {}\nLength: {}\n",
                        udp.source_port(), 
                        udp.destination_port(),
                        udp.length()
                    ));
                }
                _ => details.push_str("Type: Other (ICMP/Raw)\n"),
            }
        }
    }

    details
}

pub fn parse_packet_full(data: &[u8]) -> Option<PacketData> {
    let value = SlicedPacket::from_ethernet(data).ok()?;

    let mut source = String::from("Unknown");
    let mut dest = String::from("Unknown");
    let mut transport_str = String::from("DATA");

    // 1. Parse Network Layer (IPs)
    if let Some(net) = &value.net {
        match net {
            etherparse::NetSlice::Ipv4(ipv4) => {
                source = format!("{}", ipv4.header().source_addr());
                dest = format!("{}", ipv4.header().destination_addr());
            }
            etherparse::NetSlice::Ipv6(ipv6) => {
                source = format!("{}", ipv6.header().source_addr());
                dest = format!("{}", ipv6.header().destination_addr());
            }
            _ => {}
        }
    }

    // 2. Parse Transport Layer and Protocol
    if let Some(transport_layer) = &value.transport {
        transport_str = guess_protocol(transport_layer);
    }

    let summary = format!("{:<15} -> {:<15} | {}", source, dest, transport_str);

    Some(PacketData {
        summary,
        full_details: format_protocol_info(data),
        hex_dump: to_hex_string(data),
    })
}

fn guess_protocol(transport_slice: &etherparse::TransportSlice) -> String {
    use etherparse::TransportSlice::*;
    
    match transport_slice {
        Tcp(tcp) => {
            let port = tcp.destination_port();
            let payload = tcp.payload(); // Access payload directly from the TCP slice
            
            if port == 80 || payload.starts_with(b"GET") || payload.starts_with(b"POST") {
                "HTTP".to_string()
            } else if port == 443 || (!payload.is_empty() && payload[0] == 0x16) {
                "HTTPS/TLS".to_string()
            } else {
                format!("TCP:{}", port)
            }
        },
        Udp(udp) => {
            let port = udp.destination_port();
            let payload = udp.payload(); // Access payload directly from the UDP slice
            
            if port == 53 || payload.len() >= 2 && (payload[2] & 0x80 == 0) && port == 53 {
                "DNS".to_string()
            } else if port == 443 {
                "QUIC/UDP".to_string()
            } else {
                format!("UDP:{}", port)
            }
        },
        Icmpv4(_) => "ICMPv4".to_string(),
        Icmpv6(_) => "ICMPv6".to_string(),
    }
}
