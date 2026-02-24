use std::collections::HashMap;

pub struct ProcessResolver {
    inode_to_name: HashMap<u64, String>,
}

impl ProcessResolver {
    pub fn new() -> Self {
        let mut resolver = Self {
            inode_to_name: HashMap::new(),
        };
        resolver.refresh();
        resolver
    }

    /// Scans /proc to map socket inodes to process names
    pub fn refresh(&mut self) {
        self.inode_to_name.clear();
        if let Ok(all_proc) = procfs::process::all_processes() {
            for p in all_proc.flatten() {
                if let (Ok(stat), Ok(fds)) = (p.stat(), p.fd()) {
                    let name = stat.comm;
                    for fd in fds.flatten() {
                        if let procfs::process::FDTarget::Socket(inode) = fd.target {
                            self.inode_to_name.insert(inode, name.clone());
                        }
                    }
                }
            }
        }
    }

    /// Resolves a port to a process name using TCP and UDP tables
    pub fn resolve_port(&self, local_port: u16) -> String {
        // Check TCP Table
        if let Ok(tcp) = procfs::net::tcp() {
            if let Some(entry) = tcp.iter().find(|e| e.local_address.port() == local_port) {
                if let Some(name) = self.inode_to_name.get(&entry.inode) {
                    return name.clone();
                }
            }
        }
        // Check UDP Table
        if let Ok(udp) = procfs::net::udp() {
            if let Some(entry) = udp.iter().find(|e| e.local_address.port() == local_port) {
                if let Some(name) = self.inode_to_name.get(&entry.inode) {
                    return name.clone();
                }
            }
        }
        "Unknown".to_string()
    }
}
