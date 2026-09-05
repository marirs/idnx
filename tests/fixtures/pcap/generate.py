#!/usr/bin/env python3
"""Builds the capture fixtures.

Everything here is synthetic. Addresses come from the documentation ranges (RFC 5737
192.0.2.0/24 and 198.51.100.0/24, RFC 3849 2001:db8::/32) and hardware addresses are
locally administered (02:...), so no real host, vendor or network is identifiable. No
credentials, community strings or authentication material appear in any fixture.

Checksums are computed after the packet is assembled, so the frames are structurally valid
rather than merely plausible -- the decoders verify them, and a fixture with a stale
checksum would test the rejection path instead of the one it is named for.

Run: python3 tests/fixtures/pcap/generate.py
"""

import struct
from pathlib import Path

HERE = Path(__file__).parent

# Locally administered addresses: the second-least-significant bit of the first octet is
# set, which marks them as not globally assigned to any vendor.
ROUTER_MAC = bytes.fromhex("02005e000001")
SWITCH_MAC = bytes.fromhex("02005e000002")
HOST_MAC = bytes.fromhex("02005e000003")
BROADCAST = b"\xff" * 6


def checksum(data: bytes) -> int:
    """The one's-complement sum used by IP, ICMP, OSPF and friends."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    frame = dst + src + struct.pack("!H", ethertype) + payload
    # Ethernet's minimum is 60 bytes without the FCS; a real NIC pads, so fixtures do too.
    return frame + b"\x00" * max(0, 60 - len(frame))


def vlan(dst: bytes, src: bytes, vlan_id: int, ethertype: int, payload: bytes) -> bytes:
    tagged = struct.pack("!HH", 0x8100, vlan_id) + struct.pack("!H", ethertype) + payload
    frame = dst + src + tagged
    return frame + b"\x00" * max(0, 60 - len(frame))


def ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    src_raw = bytes(int(o) for o in src.split("."))
    dst_raw = bytes(int(o) for o in dst.split("."))
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, protocol, 0) + src_raw + dst_raw
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def udp4(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    # The IPv4 UDP checksum is optional and zero here: the decoders do not verify it, and a
    # fixture that pretended otherwise would be asserting something untested.
    datagram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ipv4(src, dst, 17, datagram)


def ipv6(src: bytes, dst: bytes, next_header: int, payload: bytes) -> bytes:
    header = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 255)
    return header + src + dst + payload


def icmpv6(src: bytes, dst: bytes, body: bytes) -> bytes:
    pseudo = src + dst + struct.pack("!I", len(body)) + b"\x00\x00\x00\x3a"
    filled = body[:2] + struct.pack("!H", checksum(pseudo + body)) + body[4:]
    return ipv6(src, dst, 58, filled)


def addr6(text: str) -> bytes:
    import ipaddress

    return ipaddress.IPv6Address(text).packed


def write(name: str, frames: list[bytes]) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for frame in frames:
        out += struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    (HERE / name).write_bytes(out)
    print(f"{name}: {len(frames)} frame(s), {len(out)} bytes")


# --- DHCP -------------------------------------------------------------------------------
def dhcp_ack(options: bytes) -> bytes:
    message = bytearray(236)
    message[0] = 2  # BOOTREPLY
    message[1] = 1
    message[2] = 6
    message[4:8] = struct.pack("!I", 0x11223344)
    message[12:16] = bytes([192, 0, 2, 50])  # ciaddr
    message[28:34] = HOST_MAC
    message += bytes([99, 130, 83, 99])
    message += bytes([53, 1, 5])  # DHCPACK
    message += options
    message += bytes([255])
    return udp4("192.0.2.1", "192.0.2.50", 67, 68, bytes(message))


# Option 1 (mask), option 3 (router) and option 121 naming a prefix beyond this link.
classless = bytes([24, 198, 51, 100, 192, 0, 2, 1])
dhcp_options = bytes([1, 4, 255, 255, 255, 0]) + bytes([3, 4, 192, 0, 2, 1])
dhcp_options += bytes([121, len(classless)]) + classless
write("dhcp_ack_option121.pcap", [ethernet(HOST_MAC, ROUTER_MAC, 0x0800, dhcp_ack(dhcp_options))])

# The same exchange with no classless routes: option 1 and 3 only.
write(
    "dhcp_ack_no_routes.pcap",
    [ethernet(HOST_MAC, ROUTER_MAC, 0x0800, dhcp_ack(bytes([1, 4, 255, 255, 255, 0]) + bytes([3, 4, 192, 0, 2, 1])))],
)


# --- Router advertisement ----------------------------------------------------------------
def prefix_option(prefix: str, length: int, flags: int) -> bytes:
    return (
        bytes([3, 4, length, flags])
        + struct.pack("!II", 2592000, 604800)
        + b"\x00\x00\x00\x00"
        + addr6(prefix)
    )


def route_option(prefix: str, length: int, preference: int, lifetime: int) -> bytes:
    # Two 8-byte units carry the first eight bytes of the prefix.
    return bytes([24, 2, length, preference]) + struct.pack("!I", lifetime) + addr6(prefix)[:8]


ra_body = bytes([134, 0, 0, 0, 64, 0]) + struct.pack("!H", 1800) + b"\x00" * 8
ra_body += prefix_option("2001:db8:1::", 64, 0xC0)  # on-link + autonomous
ra_body += prefix_option("2001:db8:2::", 64, 0x40)  # address formation only
ra_body += route_option("2001:db8:51::", 48, 0x08, 1800)  # high preference
ra_body += bytes([1, 1]) + ROUTER_MAC  # source link-layer address
write(
    "ra_pio_rio.pcap",
    [
        ethernet(
            bytes.fromhex("333300000001"),
            ROUTER_MAC,
            0x86DD,
            icmpv6(addr6("fe80::1"), addr6("ff02::1"), ra_body),
        )
    ],
)


# --- RIP ---------------------------------------------------------------------------------
def rip_entry(address: str, mask: str, metric: int, tag: int = 0) -> bytes:
    a = bytes(int(o) for o in address.split("."))
    m = bytes(int(o) for o in mask.split("."))
    return struct.pack("!HH", 2, tag) + a + m + b"\x00\x00\x00\x00" + struct.pack("!I", metric)


rip = bytes([2, 2, 0, 0])
rip += rip_entry("198.51.100.0", "255.255.255.0", 2, tag=7)
rip += rip_entry("203.0.113.0", "255.255.255.0", 16)  # withdrawal
write(
    "rip_update_and_withdrawal.pcap",
    [ethernet(bytes.fromhex("01005e000009"), ROUTER_MAC, 0x0800, udp4("192.0.2.1", "224.0.0.9", 520, 520, rip))],
)

# A request, which advertises nothing. This is the shape idnx's own probe transmits.
write(
    "rip_request.pcap",
    [
        ethernet(
            bytes.fromhex("01005e000009"),
            HOST_MAC,
            0x0800,
            udp4("192.0.2.50", "224.0.0.9", 520, 520, bytes([1, 2, 0, 0]) + struct.pack("!HH", 0, 0) + b"\x00" * 16 + struct.pack("!I", 16)),
        )
    ],
)


# --- OSPFv2 ------------------------------------------------------------------------------
def ospf_v2(kind: int, au_type: int, body: bytes) -> bytes:
    packet = bytearray([2, kind, 0, 0])
    packet += bytes([10, 0, 0, 1])  # router id
    packet += bytes([0, 0, 0, 0])  # area
    packet += b"\x00\x00"  # checksum
    packet += struct.pack("!H", au_type)
    packet += b"\x00" * 8  # authentication field, zero in these fixtures
    packet += body
    struct.pack_into("!H", packet, 2, len(packet))
    checksummed = bytearray(packet)
    checksummed[16:24] = b"\x00" * 8
    struct.pack_into("!H", packet, 12, checksum(bytes(checksummed)))
    return bytes(packet)


def summary_lsa(network: str, mask: str, age: int, metric: int) -> bytes:
    lsa = bytearray(struct.pack("!H", age) + bytes([0, 3]))
    lsa += bytes(int(o) for o in network.split("."))
    lsa += bytes([10, 0, 0, 1])  # advertising router
    lsa += struct.pack("!I", 0x80000005)
    lsa += b"\x00\x00"  # checksum, not verified per-LSA by the decoder
    lsa += b"\x00\x00"  # length
    lsa += bytes(int(o) for o in mask.split("."))
    lsa += struct.pack("!I", metric)
    struct.pack_into("!H", lsa, 18, len(lsa))
    return bytes(lsa)


lsas = summary_lsa("198.51.100.0", "255.255.255.0", 120, 10)
lsas += summary_lsa("203.0.113.0", "255.255.255.0", 3600, 20)  # MaxAge: a withdrawal
update = struct.pack("!I", 2) + lsas
write(
    "ospf_v2_update.pcap",
    [ethernet(bytes.fromhex("01005e000005"), ROUTER_MAC, 0x0800, ipv4("192.0.2.1", "224.0.0.5", 89, ospf_v2(4, 0, update)))],
)

# A hello: routers and areas, no prefixes.
hello = bytes([255, 255, 255, 0]) + struct.pack("!H", 10) + bytes([0, 1]) + struct.pack("!I", 40)
hello += bytes([10, 0, 0, 1]) + bytes([0, 0, 0, 0]) + bytes([10, 0, 0, 2])
write(
    "ospf_v2_hello.pcap",
    [ethernet(bytes.fromhex("01005e000005"), ROUTER_MAC, 0x0800, ipv4("192.0.2.1", "224.0.0.5", 89, ospf_v2(1, 0, hello)))],
)


# --- IS-IS -------------------------------------------------------------------------------
def isis_lsp(tlvs: bytes) -> bytes:
    pdu = bytearray([0x83, 27, 1, 6, 20, 1, 0, 3])
    pdu += b"\x00\x00"  # pdu length
    pdu += struct.pack("!H", 1200)  # remaining lifetime
    pdu += bytes.fromhex("1921680000010000")  # lsp id
    pdu += struct.pack("!I", 42)  # sequence
    pdu += b"\x00\x00"  # checksum
    pdu += bytes([0x03])
    pdu += tlvs
    struct.pack_into("!H", pdu, 8, len(pdu))
    # 802.2 LLC with SAP 0xFE, which is how IS-IS rides Ethernet.
    return bytes([0xFE, 0xFE, 0x03]) + bytes(pdu)


extended = struct.pack("!I", 10) + bytes([24, 198, 51, 100])
tlvs = bytes([135, len(extended)]) + extended
areas = bytes([1, 4, 3, 0x49, 0x00, 0x01])
body = isis_lsp(areas + tlvs)
frame = bytes.fromhex("0180c2000014") + SWITCH_MAC + struct.pack("!H", len(body)) + body
write("isis_lsp.pcap", [frame + b"\x00" * max(0, 60 - len(frame))])


# --- LLDP and VLAN -----------------------------------------------------------------------
def lldp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!H", (kind << 9) | len(value)) + value


lldp = lldp_tlv(1, bytes([4]) + SWITCH_MAC)  # chassis id
lldp += lldp_tlv(2, bytes([5]) + b"GigabitEthernet0/1")  # port id
lldp += lldp_tlv(3, struct.pack("!H", 120))  # time to live
lldp += lldp_tlv(5, b"test-switch")  # system name
lldp += lldp_tlv(6, b"Synthetic switch, fixture only")
lldp += lldp_tlv(7, struct.pack("!HH", 0x0014, 0x0004))  # bridge + router capable
lldp += lldp_tlv(0, b"")
write("lldp_neighbor.pcap", [ethernet(bytes.fromhex("0180c200000e"), SWITCH_MAC, 0x88CC, lldp)])

# A tagged frame carrying nothing that names a prefix: the tag is all the evidence there is.
write(
    "vlan_tag_only.pcap",
    [vlan(BROADCAST, HOST_MAC, 4, 0x0806, bytes.fromhex("0001080006040001") + HOST_MAC + bytes([192, 0, 2, 50]) + b"\x00" * 6 + bytes([192, 0, 2, 1]))],
)


# --- Mixed -------------------------------------------------------------------------------
# One capture where the same router appears through three protocols, so identity merging and
# ordering are exercised rather than one decoder at a time.
write(
    "mixed_link.pcap",
    [
        ethernet(bytes.fromhex("0180c200000e"), SWITCH_MAC, 0x88CC, lldp),
        ethernet(bytes.fromhex("333300000001"), ROUTER_MAC, 0x86DD, icmpv6(addr6("fe80::1"), addr6("ff02::1"), ra_body)),
        ethernet(bytes.fromhex("01005e000009"), ROUTER_MAC, 0x0800, udp4("192.0.2.1", "224.0.0.9", 520, 520, rip)),
        ethernet(HOST_MAC, ROUTER_MAC, 0x0800, dhcp_ack(dhcp_options)),
        vlan(BROADCAST, HOST_MAC, 4, 0x0806, bytes.fromhex("0001080006040001") + HOST_MAC + bytes([192, 0, 2, 50]) + b"\x00" * 6 + bytes([192, 0, 2, 1])),
    ],
)


# --- OSPFv3 -----------------------------------------------------------------------------
def ospf_v3_lsa(kind: int, age: int, prefix: str, length: int, metric: int) -> bytes:
    lsa = bytearray(struct.pack("!HH", age, kind))
    lsa += bytes([0, 0, 0, 1])  # link state id
    lsa += bytes([10, 0, 0, 1])  # advertising router
    lsa += struct.pack("!I", 0x80000003)
    lsa += b"\x00\x00"  # checksum
    lsa += b"\x00\x00"  # length
    lsa += struct.pack("!I", metric)
    # Prefix: length, options, reserved, then the significant bytes padded to four.
    significant = (length + 7) // 8
    padded = ((significant + 3) // 4) * 4
    lsa += bytes([length, 0, 0, 0]) + addr6(prefix)[:significant] + b"\x00" * (padded - significant)
    struct.pack_into("!H", lsa, 18, len(lsa))
    return bytes(lsa)


def ospf_v3(kind: int, body: bytes) -> bytes:
    packet = bytearray([3, kind, 0, 0])
    packet += bytes([10, 0, 0, 1])  # router id
    packet += bytes([0, 0, 0, 0])  # area
    packet += b"\x00\x00"  # checksum
    packet += b"\x00\x00"  # instance, reserved
    packet += body
    struct.pack_into("!H", packet, 2, len(packet))
    return bytes(packet)


v3_lsas = ospf_v3_lsa(0x2003, 300, "2001:db8:60::", 48, 20)
v3_lsas += ospf_v3_lsa(0x2003, 3600, "2001:db8:61::", 48, 30)  # MaxAge: a withdrawal
v3_update = ospf_v3(4, struct.pack("!I", 2) + v3_lsas)
write(
    "ospf_v3_update.pcap",
    [
        ethernet(
            bytes.fromhex("333300000005"),
            ROUTER_MAC,
            0x86DD,
            ipv6(addr6("fe80::1"), addr6("ff02::5"), 89, v3_update),
        )
    ],
)


# --- CDP over LLC/SNAP -------------------------------------------------------------------
def cdp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value) + 4) + value


cdp_body = bytes([2, 180]) + b"\x00\x00"  # version, ttl, checksum
cdp_body += cdp_tlv(0x0001, b"test-switch-cdp")  # device id
cdp_body += cdp_tlv(0x0003, b"FastEthernet0/2")  # port id
cdp_body += cdp_tlv(0x0004, struct.pack("!I", 0x0A))  # capabilities: router + switch bits
cdp_body += cdp_tlv(0x0005, b"Synthetic CDP software, fixture only")
cdp_body += cdp_tlv(0x0006, b"Synthetic platform")
snap = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00])
cdp_frame = bytes.fromhex("01000ccccccc") + SWITCH_MAC + struct.pack("!H", len(snap) + len(cdp_body))
cdp_frame += snap + cdp_body
write("cdp_neighbor.pcap", [cdp_frame + b"\x00" * max(0, 60 - len(cdp_frame))])


# --- Spanning tree -----------------------------------------------------------------------
def bpdu(bpdu_type: int) -> bytes:
    body = struct.pack("!HBB", 0x0000, 0x00 if bpdu_type == 0 else 0x02, bpdu_type)
    body += bytes([0x00])  # flags
    body += struct.pack("!H", 32768) + SWITCH_MAC  # root id
    body += struct.pack("!I", 4)  # root path cost
    body += struct.pack("!H", 32768) + SWITCH_MAC  # bridge id
    body += struct.pack("!H", 0x8001)  # port id
    body += struct.pack("!HHHH", 0, 20 * 256, 2 * 256, 15 * 256)
    frame = bytes.fromhex("0180c2000000") + SWITCH_MAC
    llc = bytes([0x42, 0x42, 0x03]) + body
    frame += struct.pack("!H", len(llc)) + llc
    return frame + b"\x00" * max(0, 60 - len(frame))


write("stp_bpdu.pcap", [bpdu(0x00)])
write("rstp_bpdu.pcap", [bpdu(0x02)])


# --- Tagged DHCP -------------------------------------------------------------------------
# A VLAN tag and a prefix disclosure in one frame: the tag is evidence of the VLAN, the
# option is evidence of the network, and neither implies the other.
write(
    "vlan_tagged_dhcp.pcap",
    [vlan(HOST_MAC, ROUTER_MAC, 12, 0x0800, dhcp_ack(dhcp_options))],
)


# --- ARP and NDP identity ----------------------------------------------------------------
def arp_reply(mac: bytes, address: str, target_mac: bytes, target: str) -> bytes:
    body = bytes.fromhex("0001080006040002") + mac
    body += bytes(int(o) for o in address.split("."))
    body += target_mac + bytes(int(o) for o in target.split("."))
    return ethernet(target_mac, mac, 0x0806, body)


def neighbour_advertisement(mac: bytes, source: str, target: str, router: bool) -> bytes:
    body = bytes([136, 0, 0, 0, 0xE0 if router else 0x60, 0, 0, 0]) + addr6(target)
    body += bytes([2, 1]) + mac  # target link-layer address
    return ethernet(
        bytes.fromhex("333300000001"),
        mac,
        0x86DD,
        icmpv6(addr6(source), addr6("ff02::1"), body),
    )


# One hardware address, one IPv4 address and one IPv6 address, learned two different ways.
write(
    "arp_ndp_identity.pcap",
    [
        arp_reply(ROUTER_MAC, "192.0.2.1", HOST_MAC, "192.0.2.50"),
        neighbour_advertisement(ROUTER_MAC, "fe80::1", "fe80::1", True),
    ],
)


# --- Malformed ---------------------------------------------------------------------------
# Each of these is structurally wrong in one specific way, and none may create topology.
truncated_ra = ra_body[: len(ra_body) - 20]
bad_ospf = bytearray(ospf_v2(4, 0, update))
bad_ospf[30] ^= 0xFF  # a byte the checksum covers
lying_rip = bytes([2, 2, 0, 0]) + rip_entry("198.51.100.0", "255.255.255.0", 2)[:12]
write(
    "malformed.pcap",
    [
        ethernet(bytes.fromhex("333300000001"), ROUTER_MAC, 0x86DD, icmpv6(addr6("fe80::1"), addr6("ff02::1"), truncated_ra)),
        ethernet(bytes.fromhex("01005e000005"), ROUTER_MAC, 0x0800, ipv4("192.0.2.1", "224.0.0.5", 89, bytes(bad_ospf))),
        ethernet(bytes.fromhex("01005e000009"), ROUTER_MAC, 0x0800, udp4("192.0.2.1", "224.0.0.9", 520, 520, lying_rip)),
        # A DHCP option claiming more bytes than the datagram holds.
        ethernet(HOST_MAC, ROUTER_MAC, 0x0800, dhcp_ack(bytes([121, 40, 24, 198, 51, 100]))),
    ],
)
