import dataclasses
from datetime import datetime

MacAddress = str
Name = str
DateTimeStr = str


@dataclasses.dataclass
class Config:
    min_packet_size: int
    access_points: dict[MacAddress, Name]
    devices: dict[MacAddress, Name]


@dataclasses.dataclass
class DeviceStats:
    bssid: MacAddress
    in_packets_count: int = 0
    in_total_bytes: int = 0
    out_packets_count: int = 0
    out_total_bytes: int = 0

    @property
    def in_avg_bytes(self) -> float:
        if self.in_packets_count == 0:
            return 0
        return self.in_total_bytes / self.in_packets_count

    @property
    def out_avg_bytes(self) -> float:
        if self.out_packets_count == 0:
            return 0
        return self.out_total_bytes / self.out_packets_count


Output = dict[datetime, dict[MacAddress, DeviceStats]]


@dataclasses.dataclass
class DeviceReadableStats:
    base_ap: Name
    in_packets_count: int = 0
    in_avg_bytes: float = 0
    out_packets_count: int = 0
    out_avg_bytes: float = 0


ReadableOutput = dict[DateTimeStr, dict[Name, DeviceReadableStats]]


# convert output to readable output
def output_to_readable_output(output: Output, config: Config) -> ReadableOutput:
    readable_output: ReadableOutput = {}
    for dt, devices in output.items():
        dt_str = dt.isoformat(sep=' ', timespec='minutes')
        readable_output[dt_str] = {}
        for mac_address, device_stats in devices.items():
            readable_output[dt_str][config.devices.get(mac_address, mac_address)] = DeviceReadableStats(
                base_ap=config.access_points.get(device_stats.bssid, device_stats.bssid),
                in_packets_count=device_stats.in_packets_count,
                in_avg_bytes=device_stats.in_avg_bytes,
                out_packets_count=device_stats.out_packets_count,
                out_avg_bytes=device_stats.out_avg_bytes,
            )
    return readable_output
