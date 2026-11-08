import struct, sys, socket
def ip_packet(proto, src, dst, payload=b'', ttl=64):
    ver_ihl = 0x45
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', ver_ihl, 0, total, 0x1234, 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    ck = (~s) & 0xFFFF
    hdr = hdr[:10] + struct.pack('!H', ck) + hdr[12:]
    return hdr + payload
def tcp_syn(sport, dport):
    return struct.pack('!HHIIBBHHH', sport, dport, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
def udp(sport, dport, data=b'abc'):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
pkts = [
 ip_packet(6, '192.168.1.5', '93.184.216.34', tcp_syn(52344, 443)),
 ip_packet(17, '192.168.1.5', '8.8.8.8', udp(53000, 53)),
 ip_packet(1, '192.168.1.5', '8.8.8.8', b'\x08\x00\x00\x00abcd'),
 ip_packet(6, '192.168.1.5', '1.1.1.1', tcp_syn(52400, 80)),
]
with open('pkts.bin','wb') as f:
    for p in pkts:
        f.write(struct.pack('!I', len(p))); f.write(p)
print('wrote', sum(len(p)+4 for p in pkts), 'bytes,', len(pkts), 'packets')
