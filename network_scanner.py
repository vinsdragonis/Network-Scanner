#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_range():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", dest="range", help="use this to set the ip range")
    options = parser.parse_args()

    if not options.range:
        parser.error("[-] Please specify IP range, use --help for more info")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_List = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # print(answered_List.summary())
    clients_list = []
    for element in answered_List:
        clients_Dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_Dict)
    return clients_list


def print_clients(clients):
    print("__________________________________")
    print(" IP\t\tMAC address\n----------------------------------")
    for client in clients:
        print(client["ip"] + "\t" + client["mac"])
    print("----------------------------------")


ipRange = get_range()
clients_List = scan(ipRange.range)
print_clients(clients_List)
