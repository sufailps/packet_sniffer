#!/usr/bin/python3
print("use sudo")
from datetime import datetime 
import sys
from scapy.all import *

net_iface = sys.argv[1] #Taking interface name
print(net_iface)

#promisceous mode transfer the interface data packets to cpu to processs and you capture from there
subprocess.call(["ifconfig",net_iface,"promisc"]) #creating another process to run command

num_of_packet = int(sys.argv[2]) #Taking number of packets

time_sec = int(sys.argv[3]) #Taking time

proto = sys.argv[4] #Taking protocol name
print(proto)

#sniff fuction call it and pass every packet in byte format
def logs(packet):
	packet.show() #show all packets
	print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)}")


if proto == "all":
	sniff(iface = net_iface ,count = num_of_packet, timeout = time_sec, prn=logs ) 
elif proto == "ARP" or proto == "arp":
	
	sniff(iface = net_iface, count = num_of_packet,timeout = time_sec , prn = logs , filter = "arp") 
elif proto == "icmp":
	sniff(iface = net_iface, count = num_of_packet,timeout = time_sec , prn = logs , filter = "icmp")
else:
	print("Wrong protocol")
