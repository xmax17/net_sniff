use etherparse::{SlicedPacket};
use ratatui::text::{Line,Span};
use ratatui::style::{Color,Style};

pub fn parse_packet_to_line(data: &[u8]) -> Option<Line<'static>> {
   let value = SlicedPacket::from_ethernet(data).ok()?;

   let mut source = String::from("Unkown");
   let mut dest = String::from("Unkown");
   let mut transport = String::from("DATA");

  if let Some(net) = value.net {
      match net {
          etherparse::NetSlice::Ipv4(ipv4) => {
              source = format!("{}",ipv4.header().source_addr()); 
              dest = format!("{}",ipv4.header().destination_addr());
          }
          etherparse::NetSlice::Ipv6(ipv6) => {
              source = format!("{}",ipv6.header().source_addr()); 
              dest = format!("{}",ipv6.header().destination_addr());
          }
          _ => {}
      }
  }

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

  let line = Line::from(vec![
      Span::styled(format!("{:<15}", source), Style::default().fg(Color::Cyan)),
      Span::raw(" -> "),
      Span::styled(format!("{:<15}",dest), Style::default().fg(Color::LightRed)),
      Span::raw(" | "),
      Span::styled(transport, Style::default().fg(Color::Magenta)),

  ]);
 Some(line) 
}
