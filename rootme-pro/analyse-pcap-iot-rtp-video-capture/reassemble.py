#!/usr/bin/env python3
"""Depacketize RFC 6184 H.264/RTP payloads into an Annex-B elementary stream."""
import sys

rows = []
with open("files/rtp_payloads.tsv") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 4 or not parts[3]:
            continue
        seq, ts, marker, payload_hex = parts
        rows.append((int(seq), payload_hex))

# sort by RTP sequence number with 16-bit wraparound handling
rows.sort(key=lambda r: r[0])

out = bytearray()
fu_buf = None  # (nal_header_byte, bytearray of fragment payload)

START_CODE = b"\x00\x00\x00\x01"

for seq, hexstr in rows:
    payload = bytes.fromhex(hexstr)
    if not payload:
        continue
    nal0 = payload[0]
    nal_type = nal0 & 0x1F

    if nal_type == 28:  # FU-A
        fu_header = payload[1]
        start = bool(fu_header & 0x80)
        end = bool(fu_header & 0x40)
        orig_type = fu_header & 0x1F
        reconstructed_nal_header = (nal0 & 0xE0) | orig_type
        frag_data = payload[2:]
        if start:
            fu_buf = bytearray()
            fu_buf.append(reconstructed_nal_header)
        if fu_buf is not None:
            fu_buf.extend(frag_data)
        if end and fu_buf is not None:
            out += START_CODE + bytes(fu_buf)
            fu_buf = None

    elif nal_type == 24:  # STAP-A
        offset = 1
        while offset + 2 <= len(payload):
            size = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            nal = payload[offset:offset + size]
            offset += size
            out += START_CODE + nal

    elif 1 <= nal_type <= 23:  # single NAL unit
        out += START_CODE + payload

    else:
        sys.stderr.write(f"seq={seq}: unhandled NAL type {nal_type}\n")

with open("files/stream.h264", "wb") as f:
    f.write(out)

print(f"wrote {len(out)} bytes from {len(rows)} RTP packets")
