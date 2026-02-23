use etherparse::SlicedPacket;
use ratatui::text::Line;

/// This struct holds all the data for a single packet.
/// It is sent from the capture thread to the main UI loop.
pub struct PacketData {
    pub summary: String,       // The short one-liner for the list feed
    pub full_details: String,  // Protocol metadata for the inspector
    pub hex_dump: String,      // The raw bytes formatted as hex
}

/// Converts raw bytes into a classic hex dump format (16 bytes per line)
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

/// Formats high-level information about the packet.
/// You can expand this logic as you need more specific protocol data.
pub fn format_protocol_info(bytes: &[u8]) -> String {
    format!(
        "--- PACKET METADATA ---\n\
         Size: {} bytes\n\n\
         --- PARSER STATUS ---\n\
         Parsing via etherparse...\n\
         (Use arrow keys to see full Hex Dump below)",
        bytes.len()
    )
}

/// The main parsing function that converts raw packet bytes 
/// into our UI-friendly PacketData struct.
pub fn parse_packet_full(data: &[u8]) -> Option<PacketData> {
    // Attempt to slice the packet into its protocol layers
    let value = SlicedPacket::from_ethernet(data).ok()?;

    let mut source = String::from("Unknown");
    let mut dest = String::from("Unknown");
    let mut transport = String::from("DATA");

    // 1. Parse Network Layer (IPv4 / IPv6)
    if let Some(net) = value.net {
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

    // 2. Parse Transport Layer (TCP / UDP)
    if let Some(transport_layer) = value.transport {
        match transport_layer {
            etherparse::TransportSlice::Tcp(tcp) => {
                transport = format!("TCP:{}", tcp.destination_port());
            }
            etherparse::TransportSlice::Udp(udp) => {
                transport = format!("UDP:{}", udp.destination_port());
            }
            _ => {}
        }
    }

    // 3. Construct the summary string
    // Format: "192.168.1.1 -> 1.1.1.1 | TCP:443"
    let summary = format!("{:<15} -> {:<15} | {}", source, dest, transport);

    Some(PacketData {
        summary,
        full_details: format_protocol_info(data),
        hex_dump: to_hex_string(data),
    })
}
