//! 常见端口 → 服务名映射 + 端口列表解析。

use crate::services;

pub fn service_name(port: u16) -> &'static str {
    match port {
        1 => "tcpmux",
        7 => "echo",
        9 => "discard",
        13 => "daytime",
        17 => "qotd",
        19 => "chargen",
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        37 => "time",
        39 => "rlp",
        42 => "wins",
        43 => "whois",
        49 => "tacacs",
        53 => "domain",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        70 => "gopher",
        79 => "finger",
        80 => "http",
        81 => "http-alt",
        88 => "kerberos",
        102 => "iso-tsap",
        105 => "csnet-ns",
        109 => "pop2",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        177 => "xdmcp",
        179 => "bgp",
        194 => "irc",
        201 => "at-rtmp",
        213 => "ipx",
        220 => "imap3",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        464 => "kpasswd",
        465 => "smtps",
        500 => "isakmp",
        512 => "exec",
        513 => "login",
        514 => "shell",
        515 => "printer",
        520 => "route",
        524 => "ncp",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        623 => "asf-rmcp",
        631 => "ipp",
        636 => "ldaps",
        646 => "ldp",
        873 => "rsync",
        888 => "accessbuilder",
        902 => "vmware-auth",
        989 => "ftps-data",
        990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1023 => "netvenuechat",
        1025 => "NFS-or-IIS",
        1080 => "socks",
        1194 => "openvpn",
        1241 => "nessus",
        1433 => "ms-sql-s",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1701 => "l2tp",
        1723 => "pptp",
        1900 => "upnp",
        2000 => "cisco-sccp",
        2049 => "nfs",
        2121 => "ftp-alt",
        2222 => "ssh-alt",
        2375 => "docker",
        2376 => "docker-ssl",
        3000 => "grafana/node",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        4000 => "icq",
        4444 => "krb524",
        5000 => "upnp-dev",
        5060 => "sip",
        5061 => "sips",
        5222 => "xmpp",
        5353 => "mdns",
        5357 => "wsd-api",
        5432 => "postgresql",
        5555 => "adb-server",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5985 => "wsman",
        5986 => "wsmans",
        6379 => "redis",
        6443 => "kube-api",
        7000 => "afs3-fileserver",
        7070 => "realserver",
        8000 => "http-alt",
        8008 => "http",
        8009 => "ajp13",
        8080 => "http-proxy",
        8081 => "http-alt",
        8088 => "http-alt",
        8090 => "http-alt",
        8139 => "puppet",
        8443 => "https-alt",
        8888 => "sun-answerbook",
        9000 => "cslistener",
        9090 => "zeus-admin",
        9091 => "xmltec-xmlmail",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        9418 => "git",
        9999 => "abyss",
        10000 => "webmin",
        11211 => "memcache",
        15672 => "rabbitmq-mgmt",
        25565 => "minecraft",
        27017 => "mongodb",
        32400 => "plex",
        49152 => "unknown",
        _ => "unknown",
    }
}

/// 常见端口集（nmap 风格 top-N 精简版）
static TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 515, 548,
    554, 587, 631, 636, 873, 993, 995, 1025, 1080, 1433, 1434, 1521, 1723, 1900, 2049, 2121,
    2222, 2375, 3000, 3306, 3389, 5060, 5222, 5353, 5432, 5555, 5601, 5900, 5985, 6379, 6443,
    7000, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9100, 9200, 9418, 10000,
    11211, 15672, 25565, 27017, 32400,
];

/// 快速发现探测端口（用于判断主机是否存活）
pub static DISCOVERY_PORTS: &[u16] = &[443, 80, 22, 445, 3389, 8080, 139, 53, 23, 8000];

/// 解析端口规格:
///   "22,80,443" | "1-1024" | "top100" | "all"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim().to_ascii_lowercase();
    if spec.is_empty() {
        return Ok(Vec::new());
    }
    if spec == "all" {
        return Ok((1..=65535u16).collect());
    }
    if spec == "top" || spec == "top100" || spec == "common" {
        return Ok(TOP_PORTS.to_vec());
    }
    if let Some(n) = spec.strip_prefix("top") {
        if let Ok(k) = n.parse::<usize>() {
            let mut v = TOP_PORTS.to_vec();
            v.truncate(k.min(v.len()));
            return Ok(v);
        }
    }
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u32 = a.trim().parse().map_err(|_| format!("非法端口: {}", a))?;
            let end: u32 = b.trim().parse().map_err(|_| format!("非法端口: {}", b))?;
            if start == 0 || end > 65535 || end < start {
                return Err(format!("非法端口范围: {}", part));
            }
            for p in start..=end {
                out.push(p as u16);
            }
        } else {
            let p: u32 = part.parse().map_err(|_| format!("非法端口: {}", part))?;
            if p == 0 || p > 65535 {
                return Err(format!("非法端口: {}", part));
            }
            out.push(p as u16);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > 60000 {
        return Err("端口数量过多".into());
    }
    Ok(out)
}

pub fn top_ports() -> Vec<u16> {
    services::TOP_PORTS.to_vec()
}
