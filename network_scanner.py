#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_List = scapy.srp(arp_request_broadcast, timeout=1)[0]

    # print(answered_List.summary())
    print("__________________________________")
    print(" IP\t\tMAC address\n----------------------------------")
    for element in answered_List:
        print(" " + element[1].psrc +"\t" + element[1].hwsrc)


scan("10.0.2.1/24")
