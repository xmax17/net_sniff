use maxminddb::geoip2;
use std::net::IpAddr;
use std::str::FromStr;

pub struct GeoResolver {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoResolver {
    pub fn new() -> Self {
        let reader = maxminddb::Reader::open_readfile("GeoLite2-City.mmdb")
            .expect("Table 'GeoLite2-Country.mmdb' not found. Download it from MaxMind.");
        Self { reader }
    }

    pub fn resolve(&self, ip_str: &str) -> String {
        // Parse the string into a real IP type
        let ip = match IpAddr::from_str(ip_str) {
            Ok(addr) => addr,
            Err(_) => return " .. ".to_string(),
        };

        // Instant local lookup
        match self.reader.lookup::<geoip2::Country>(ip) {
            Ok(country) => country
                .country
                .and_then(|c| c.iso_code)
                .unwrap_or("--")
                .to_string(),
            Err(_) => "--".to_string(),
        }
    }
}
