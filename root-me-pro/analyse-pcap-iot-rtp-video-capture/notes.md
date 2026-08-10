# Analyse PCAP - IoT - RTP Video Capture (Root-Me Pro, Network, Medium, 500pts)

## Step 1 — protocol/port identification

Copied capture.pcapng into files/.

`tshark -r files/capture.pcapng -q -z io,phs` shows most UDP traffic is DNS/QUIC/noise,
but one conversation stands out:

`tshark -r files/capture.pcapng -q -z conv,udp`
  172.18.158.1:33781 <-> 172.18.158.134:5004   323 frames, 309 KB, one-directional (camera -> viewer)

tshark doesn't auto-dissect port 5004 as RTP by default (not in its heuristic list for this
capture), so it showed as raw "data" in the protocol hierarchy. Forced dissection:

`tshark -r files/capture.pcapng -Y "udp.port==5004" -d udp.port==5004,rtp -T fields -e rtp.version -e rtp.p_type -e rtp.seq`
  -> rtp.version=2, payload type=96 (dynamic/video), incrementing sequence numbers. Confirmed RTP.

Companion RTCP traffic found on port 5005 (RTP port + 1, standard pairing):
`tshark -r files/capture.pcapng -Y rtcp` -> 172.18.158.1:33782 <-> 172.18.158.134:5005

## Answer
Protocol: RTP
Port: 5004

Flag format requested: PROTOCOLE:PORT -> RTP:5004

## Step 2 — codec identification

Payload type 96 is dynamic (no static RTP profile mapping), and no SDP/RTSP signaling was
captured to declare it out-of-band, so identified codec by inspecting raw RTP payload bytes.

`tshark -r files/capture.pcapng -Y "udp.port==5004 && ip.src==172.18.158.1 && rtp.seq==77" -d udp.port==5004,rtp -T fields -e rtp.payload`

First payload byte 0x18 = NAL header: forbidden=0, nal_ref_idc=0, nal_unit_type=24 (STAP-A,
RFC 6184 aggregation packet) -> confirms H.264 RTP payload format (RFC 6184).

Aggregated NALs include a type-6 SEI NAL carrying the x264 encoder identification string
(plaintext, since feed is unencrypted):
  "x264 - core 164 r3108 31e19f9 - H.264/MPEG-4 AVC codec - Copyleft 2003-2023 -
   http://www.videolan.org/x264.html - options: cabac=0 ref=1 deblock=... ..."

## Answer (Step 2)
Codec: H.264 (ITU-T H.264 / MPEG-4 Part 10 AVC), encoded with x264 (core 164).

## Step 3 — reconstruct the video stream

Noticed each RTP seq number appeared to occur twice in a naive dump — turned out to be a red
herring: the duplicates are actually ICMP error packets (frame.protocols contains icmp)
carrying a copy of the original UDP packet as their payload (router/host complaining about
the RTP traffic). Filtering `udp.port==5004 && !icmp` gives exactly 323 genuine unidirectional
RTP packets, one per seq number, camera(172.18.158.1) -> viewer(172.18.158.134).

Dumped seq/timestamp/marker/payload with tshark:
  `tshark -r files/capture.pcapng -Y "udp.port==5004 && !icmp" -d udp.port==5004,rtp -T fields -e rtp.seq -e rtp.timestamp -e rtp.marker -e rtp.payload > files/rtp_payloads.tsv`

Wrote reassemble.py implementing RFC 6184 depacketization (STAP-A aggregation, FU-A
fragmentation, single NAL passthrough) sorted by RTP sequence number, prefixing each
reconstructed NAL with an Annex-B start code (00 00 00 01) -> files/stream.h264 (291,642 bytes).

No ffmpeg/sudo available (sudo needs a password in this environment, contrary to the CLAUDE.md
note) — installed `imageio-ffmpeg` via pip (bundles a static ffmpeg binary, no root needed).

`ffmpeg -i files/stream.h264` confirms: Video: h264 (Constrained Baseline), yuv420p, 1280x720,
25 fps — clean decode, no errors, confirming correct depacketization.

Extracted all 204 frames as PNG and as stream.mp4. The video shows title text "SOC CHALLENGE"
with a flag typed out character-by-character (green/glitch reveal effect) below it. Frame 120
onward shows the fully-typed, stable flag text.

## Answer (Step 3)
The reconstructed video contains the text: SOC CHALLENGE, and reveals the flag:
RM{ce332e58031}
