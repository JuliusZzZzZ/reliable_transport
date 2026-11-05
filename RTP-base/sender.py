#!/usr/bin/env python3
"""RTP sender (Part 1) - Go-Back-N style sliding window with cumulative ACKs, over UDP."""
import argparse
import socket
import struct
import sys
import time
import zlib

START, END, DATA, ACK = 0, 1, 2, 3
HDR = struct.Struct("!IIII")        # type, seq_num, length, checksum (32-bit each)
MAX_PKT = 1472                      # 1500 - 20 (IP) - 8 (UDP)
MAX_DATA = MAX_PKT - HDR.size       # payload bytes per packet
TIMEOUT = 0.5                       # 500 ms retransmission timer


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
    ap.add_argument("receiver_ip", help="IP of the host running receiver")
    ap.add_argument("receiver_port", type=int, help="port receiver listens on")
    ap.add_argument("window_size", type=int, help="max number of outstanding packets")
    args = ap.parse_args()

    dest = (args.receiver_ip, args.receiver_port)
    window = max(1, args.window_size)

    data = sys.stdin.buffer.read()
    chunks = [data[i:i + MAX_DATA] for i in range(0, len(data), MAX_DATA)]
    n = len(chunks)                                  # DATA packets have seq 1..n
    pkts = [None] + [make_packet(DATA, i + 1, c) for i, c in enumerate(chunks)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def wait_ack(deadline):
        """Block until a valid ACK arrives (return its seq) or deadline passes (None)."""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                raw, _ = sock.recvfrom(2048)
            except socket.timeout:
                return None
            except OSError:
                continue
            p = parse_packet(raw)
            if p is not None and p[0] == ACK:
                return p[1]

    # ---- handshake: START (seq 0) -> ACK (seq 1) ----
    start_pkt = make_packet(START, 0)
    while True:
        sock.sendto(start_pkt, dest)
        deadline = time.monotonic() + TIMEOUT
        got = False
        while True:
            ack = wait_ack(deadline)
            if ack is None:
                break
            if ack == 1:
                got = True
                break
        if got:
            break

    # ---- data transfer: sliding window, cumulative ACK ----
    base = 1            # oldest unacknowledged seq
    nxt = 1             # next seq to send for the first time
    timer = time.monotonic()
    while base <= n:
        while nxt <= n and nxt < base + window:
            sock.sendto(pkts[nxt], dest)
            nxt += 1
        ack = wait_ack(timer + TIMEOUT)
        if ack is None:                              # timeout: resend the whole window
            for s in range(base, nxt):
                sock.sendto(pkts[s], dest)
            timer = time.monotonic()
        elif base < ack <= nxt:                      # window moves forward
            base = ack
            timer = time.monotonic()
        # otherwise: duplicate / stale ACK -> ignore

    # ---- teardown: END (seq n+1) -> ACK (seq n+2), give up after 500 ms ----
    end_seq = n + 1
    end_pkt = make_packet(END, end_seq)
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        sock.sendto(end_pkt, dest)
        retry = min(deadline, time.monotonic() + 0.1)
        while True:
            ack = wait_ack(retry)
            if ack is None:
                break
            if ack == end_seq + 1:
                return


if __name__ == "__main__":
    main()
