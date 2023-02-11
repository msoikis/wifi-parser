import collections
import logging
from datetime import datetime

import dpkt.pcap

import models

BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"

logger = logging.getLogger()


def parse_802_11_pcap(pcap: dpkt.pcap.Reader, config: models.Config) -> models.Output:
    # Initialize output data structure
    output = collections.defaultdict(dict)

    # Iterate over all packets
    i = 0
    for timestamp, packet in pcap:
        i += 1
        try:
            # Parse 802.11 (WLAN) packet
            wifi_packet = dpkt.ieee80211.IEEE80211(packet)
        except dpkt.UnpackError as e:
            # DPKT fails to parse some 802.11 packets, so we just ignore them
            logger.debug(f"Error parsing packet {i} ({len(packet)} bytes): {e!r}")
            continue

        # Ignore packets that are too small
        if len(packet) < config.min_packet_size:
            continue

        packet_time = get_datetime_minute_resolution(timestamp)

        # Get source and destination MAC addresses
        try:
            src_mac, dst_mac = extract_packet_src_and_dst_mac_addresses(wifi_packet)
        except ValueError:
            logger.warning(f"Failed to extract src & dst mac addresses from wifi packet {i} ({len(packet)} bytes)")
            continue

        # Ignore broadcast/multicast packets
        if is_broadcast_or_multicast_mac_address(src_mac) or is_broadcast_or_multicast_mac_address(dst_mac):
            continue

        # Extract BSSID and device MAC address
        if src_mac in config.access_points:
            assert dst_mac not in config.access_points
            device_mac = dst_mac
            bssid = src_mac
        elif dst_mac in config.access_points:
            assert src_mac not in config.access_points
            device_mac = src_mac
            bssid = dst_mac
        else:
            logger.warning(f"Packet does not belong to preconfigured access points {i} ({len(packet)} bytes)")
            continue

        # Update output data structure
        time_slot = output[packet_time]
        if device_mac not in time_slot:
            time_slot[device_mac] = models.DeviceStats(bssid=bssid)
        if src_mac == device_mac:
            time_slot[device_mac].out_packets_count += 1
            time_slot[device_mac].out_total_bytes += len(packet)
        else:
            assert dst_mac == device_mac
            time_slot[device_mac].in_packets_count += 1
            time_slot[device_mac].in_total_bytes += len(packet)

        logger.debug(f"Wifi packet {i}: {len(packet)} bytes, {packet_time}, {src_mac} -> {dst_mac}")
        logger.debug(f"Device {device_mac}: {time_slot[device_mac]}")

    return output


def get_datetime_minute_resolution(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp).replace(second=0, microsecond=0)


def extract_packet_src_and_dst_mac_addresses(packet: dpkt.ieee80211.IEEE80211) -> tuple[str, str]:
    # in most cases they are in data_frame.src and data_frame.dst
    if hasattr(packet, "data_frame"):
        src_mac = mac_6_bytes_to_hex_str_mac_address(packet.data_frame.src)
        dst_mac = mac_6_bytes_to_hex_str_mac_address(packet.data_frame.dst)
        bssid = mac_6_bytes_to_hex_str_mac_address(packet.data_frame.bssid)

        # There are packets where the address is slightly different from the BSSID (in last byte).
        # In this case we assume that the address is the BSSID.
        if src_mac[:-2] == bssid[:-2]:
            src_mac = bssid
        if dst_mac[:-2] == bssid[:-2]:
            dst_mac = bssid
    # in some cases they are in mgmt.src and mgmt.dst
    elif hasattr(packet, "mgmt"):
        src_mac = mac_6_bytes_to_hex_str_mac_address(packet.mgmt.src)
        dst_mac = mac_6_bytes_to_hex_str_mac_address(packet.mgmt.dst)
    else:
        raise ValueError(f"Failed to extract src & dst mac addresses from packet: {packet}")
    return src_mac, dst_mac


def mac_6_bytes_to_hex_str_mac_address(mac_address: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_address)


def is_broadcast_or_multicast_mac_address(mac_address: str) -> bool:
    return mac_address == BROADCAST_MAC_ADDRESS or is_multicast_mac_address(mac_address)


def is_multicast_mac_address(mac_address: str) -> bool:
    return mac_address.startswith("01:00:5e") or mac_address.startswith("33:33")
