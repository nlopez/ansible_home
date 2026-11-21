#!/usr/bin/env python3
"""Relay NetFlow v9 from OPNsense to the local Datadog agent.

OPNsense's v9 template lists OUT_BYTES (23) and OUT_PKTS (24) after IN_*, and
always sends 0 in them. The agent's goflow2 decoder lets the later field
overwrite the real counts, so every flow reports 0 bytes. Renaming the two
template field types makes the decoder ignore them; data records are untouched.
Packets are forwarded with the exporter's source address because the agent
identifies the device by it.
"""
import socket
import struct
import sys

LISTEN_PORT, FORWARD_ADDR = int(sys.argv[1]), (sys.argv[2], int(sys.argv[3]))
RENAME = {23: 0xF017, 24: 0xF018}


def fix(pkt):
    if len(pkt) < 20 or struct.unpack(">H", pkt[:2])[0] != 9:
        return pkt
    out, pos = bytearray(pkt), 20
    while pos + 4 <= len(out):
        fid, length = struct.unpack(">HH", out[pos:pos + 4])
        if length < 4:
            break
        if fid == 0:  # template flowset
            q = pos + 4
            while q + 4 <= pos + length:
                _, count = struct.unpack(">HH", out[q:q + 4])
                q += 4
                for _ in range(count):
                    ftype, flen = struct.unpack(">HH", out[q:q + 4])
                    if ftype in RENAME:
                        out[q:q + 2] = struct.pack(">H", RENAME[ftype])
                    q += 4
        pos += length
    return bytes(out)


def ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    s = sum(struct.unpack(">10H", hdr))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return hdr[:10] + struct.pack(">H", ~s & 0xFFFF) + hdr[12:] + udp


def main():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("0.0.0.0", LISTEN_PORT))
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    while True:
        data, (src, sport) = rx.recvfrom(65535)
        tx.sendto(ip_udp(src, FORWARD_ADDR[0], sport, FORWARD_ADDR[1], fix(data)),
                  FORWARD_ADDR)


if __name__ == "__main__" and len(sys.argv) == 4:
    main()
