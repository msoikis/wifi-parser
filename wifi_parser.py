"""
Usage: python wifi_parser.py --config <config.json> --input <file.cap>

This script will parse <file.cap> file using DPKT package and configuration provided by <config.json>.

The config file format:
{
    "min_packet_size": 90,  # minimum packet size to be parsed
    "access_points": {
        mac_address: name,  # mac address of access point and its name
        ...
    },
    "devices": {
        mac_address: name,  # mac address of device and its name
        ...
    }
}

"""

import argparse
import json
import logging

import dpkt
from devtools import debug

import models
from parse_802_11_pcap import parse_802_11_pcap
import log_utils

logger = logging.getLogger()


def main():
    log_utils.set_logger("wifi_parser.log", logging.INFO)
    args = get_args()
    config = get_config(args.config)
    parse(args, config)


def get_args() -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--config", help="JSON file with configuration")
    arg_parser.add_argument("--input", help="Input 802.11 capture file to parse")
    args = arg_parser.parse_args()
    logger.info(f'{__file__} {args}')
    return args


def get_config(config_path: str) -> models.Config:
    with open(config_path) as config_file:
        # load config as models.Config from JSON config_file
        config = models.Config(**json.load(config_file))
        logger.info(debug.format(config))
        return config


def parse(args: argparse.Namespace, config: models.Config):
    with open(args.input, "rb") as input_file:
        pcap = dpkt.pcap.Reader(input_file)
        output = parse_802_11_pcap(pcap, config)

    readable_output = models.output_to_readable_output(output, config)
    logger.info(debug.format(readable_output))


if __name__ == "__main__":
    main()
