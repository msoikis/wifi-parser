Instructions & Usage
====================

This project analyzes a raw wifi traffic capture and outputs statistics on devices: 
incoming and outgoing number of packets and packets size, per minute.

To create the capture file, follow the instructions in [wifi_capture.md](wifi_capture.md).

Before running the script, create/update the `config.json` file with the correct values 
for your network's access points and devices in order to make the output more readable.

Run the `wifi_parser.py` script to parse the capture file. 

See [run-up folder](run-up) for an example:

`config.json` - Mapping of access points and devices MAC addresses to names.

`home-149-01.cap` - Raw wifi traffic capture file.

`run-up.sh` - Script to run the parser with arguments of the above files.

`wifi_parser.log` - Log file with the output of the parser.
