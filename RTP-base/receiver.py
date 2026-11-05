#!/usr/bin/env python3
"""RTP receiver (Part 2) - buffers out-of-order packets, sends cumulative ACKs, over UDP."""
import argparse
import socket
import struct
import sys
import zlib

START, END, DATA, ACK = 0, 1, 2, 3
HDR = struct.Struct("!IIII")        # type, seq_num, length, checksum (32-bit each)
MAX_PKT = 1472
MAX_DATA = MAX_PKT - HDR.size


def make_packet(ptype, seq, payload=b""):
    hdr0 = HDR.pack(ptype, seq, len(payload), 0)
    checksum = zlib.crc32(hdr0 + payload) & 0xFFFFFFFF
    return HDR.pack(ptype, seq, len(payload), checksum) + payload


def parse_packet(raw):
    """Return (type, seq, payload) or None if malformed / corrupted."""
    if len(raw) < HDR.size:
        return None
    ptype, seq, length, checksum = HDR.unpack_from(raw)
    if length > MAX_DATA or len(raw) < HDR.size + length:
        return None
    payload = raw[HDR.size:HDR.size + length]
    if zlib.crc32(HDR.pack(ptype, seq, length, 0) + payload) & 0xFFFFFFFF != checksum:
        return None
    return ptype, seq, payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receiver_ip", help="IP to bind to")
    ap.add_argument("receiver_port", type=int, help="port to listen on")
    ap.add_argument("window_size", type=int, help="max number of outstanding packets")
    args = ap.parse_args()
    window = max(1, args.window_size)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.receiver_ip, args.receiver_port))
    out = sys.stdout.buffer

    connected = False
    peer = None
    expected = 1                    # next in-order seq we are waiting for
    buf = {}                        # out-of-order DATA packets: seq -> payload
    seen_data = False

    while True:
        raw, addr = sock.recvfrom(2048)
        p = parse_packet(raw)
        if p is None:               # corrupted -> drop silently, no ACK
            continue
        ptype, seq, payload = p

        if ptype == START:
            if not connected:       # only one sender at a time
                connected, peer = True, addr
                expected, buf, seen_data = 1, {}, False
                sock.sendto(make_packet(ACK, 1), addr)
            elif addr == peer and not seen_data:
                sock.sendto(make_packet(ACK, 1), addr)   # our ACK was probably lost
            continue

        if not connected or addr != peer:
            continue

        if ptype == DATA:
            seen_data = True
            if expected <= seq < expected + window:
                if seq not in buf:
                    buf[seq] = payload
                while expected in buf:              # deliver everything now in order
                    out.write(buf.pop(expected))
                    expected += 1
                sock.sendto(make_packet(ACK, expected), addr)   # cumulative ACK
            elif seq < expected:                    # old duplicate: tell sender where we are
                sock.sendto(make_packet(ACK, expected), addr)
            # seq >= expected + window: outside the window -> drop

        elif ptype == END:
            if seq == expected:                     # all data delivered
                sock.sendto(make_packet(ACK, seq + 1), addr)
                out.flush()
                return


if __name__ == "__main__":
    main()
