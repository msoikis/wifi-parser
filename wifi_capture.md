How to capture wifi traffic on a specific wifi network?
=======================================================

The following commands are used to capture wifi traffic on a specific channel, to a file:

To check which channel is configured on `wlp8s0` interface:

`iwlist wlp8s0 channel`


To kill processes that might interfere with `airmon-ng`:

`sudo airmon-ng check kill`


To start monitor mode on `wlp8s0` interface:

`sudo airmon-ng start wlp8s0`


To check the result:

`iwconfig`


To scan for networks:

`sudo airodump-ng wlp8s0mon`


To capture wifi traffic on a specific channel, to a file:

`sudo airodump-ng -c 149 -w sniff_file wlp8s0mon`


To stop monitor mode:

`sudo airmon-ng stop wlp8s0mon`


To start NetworkManager and restore network connectivity:

`sudo systemctl start NetworkManager.service`
