use std::collections::HashMap;

#[cfg(target_os = "linux")]
use procfs;

// In sysinfo 0.30+, traits like ProcessExt/SystemExt are gone.
// We just need the main types.
#[cfg(target_os = "macos")]
use sysinfo::System;

pub struct ProcessResolver {
    #[allow(dead_code)]
    inode_to_name: HashMap<u64, String>,
    #[cfg(target_os = "macos")]
    sys: System,
}

impl ProcessResolver {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        let mut sys = System::new_all();
        #[cfg(target_os = "macos")]
        sys.refresh_all();

        let mut resolver = Self {
            inode_to_name: HashMap::new(),
            #[cfg(target_os = "macos")]
            sys,
        };
        resolver.refresh();
        resolver
    }

    pub fn refresh(&mut self) {
        self.inode_to_name.clear();

        #[cfg(target_os = "linux")]
        {
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

        #[cfg(target_os = "macos")]
        {
            // Direct method call, no trait import needed in 0.30+
            self.sys.refresh_processes();
        }
    }

    pub fn resolve_port(&self, _local_port: u16) -> String {
        #[cfg(target_os = "linux")]
        {
            if let Ok(tcp) = procfs::net::tcp() {
                if let Some(entry) = tcp.iter().find(|e| e.local_address.port() == _local_port) {
                    if let Some(name) = self.inode_to_name.get(&entry.inode) {
                        return name.clone();
                    }
                }
            }
            if let Ok(udp) = procfs::net::udp() {
                if let Some(entry) = udp.iter().find(|e| e.local_address.port() == _local_port) {
                    if let Some(name) = self.inode_to_name.get(&entry.inode) {
                        return name.clone();
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Placeholder for Mac logic
            "macOS-App".to_string()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            "Unknown".to_string()
        }
    }
}
