#Wonderful Tiny Functionless NAT

This program is built under linux environment, user need gcc and libpcap.
If you don't have libpcap library, please download it for compiling.
You can find the source of libpcap here: http://www.tcpdump.org/

##Compile
	Refer to Makefile, just type make.

##Usage
	./wtfnat OUT_DEVICE_NAME LAN_DEVICE_NAME [RULE_FILE_NAME]
	which OUT_DEVICE_NAME is your device with the physical ip,
	LAN_DEVICE_NAME is the device connected to clients.

##Firewall
	Open a text file and fill in the addresses or ports to block.
	For example, if you want to block the packets from 1.2.3.4 or port 21,
	Your content in the rule file should be:
	ip 1.2.3.4
	port 21

