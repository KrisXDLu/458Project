import csv
import numpy as np 
import matplotlib.pyplot as plt
import time
import datetime
import math

# No.,Time,Source,Protocol,
# 0    1    2      3
# Length,Encapsulation type,Source IP,Destination IP,
#  4       5                   6         7
# Source Port,Destination Port,Arrival Time,Protocols in frame,
#   8              9               10            11
# data,IP Header,TCP Header,Flags,
#   12   13        14        15
# Syn,ACK,Fin,Reset,
#  16  17  18  19
# ACK No,TCP Segment Len,Info
# 20      21              22
def plot(data, name):
    data = np.sort(data)
    y = 1. * np.arange(len(data))/(len(data)-1)
    plt.plot(data, y)
    # data = np.log(data)
    plt.scatter(data, y)
    plt.xscale('log', basex=math.e)
    plt.xlim(1, 55)
    # plt.show()
    plt.savefig(name)
    plt.close()

def total(packets):
    total = []
    for pkt in packets:
        protocol = pkt[11]
        # if 'ip' in protocol or 'icmp' in protocol:
        total.append(pkt[4])
    return total

def isIP(packets):
    ip = []
    ip_header = []
    for pkt in packets:
        protocol = pkt[11]
        if 'ip' in protocol or 'icmp' in protocol:
            ip.append(pkt[4])
            ip_header.append(pkt[13])
    return ip, ip_header
    
def isNonIP(packets):
    nonIp = []
    for pkt in packets:
        protocol = pkt[11]
        if ('ip' not in protocol) and ('icmp' not in protocol):
            nonIp.append(pkt[4])
    return nonIp

def isTCP(packets):
    tcp = []
    tcp_header = []
    for pkt in packets:
        protocol = pkt[11]
        if 'tcp' in protocol:
            tcp.append(pkt[4])
            tcp_header.append(pkt[14])
    return tcp, tcp_header
    
def isUDP(packets):
    udp = []
    udp_header = []
    for pkt in packets:
        protocol = pkt[11]
        if 'udp' in protocol:
            udp.append(pkt[4])
    return udp, udp_header

if __name__ == "__main__":   
    # ip = np.array([])
    # udp = np.array([])
    # tcp = np.array([])
    # nonIP = np.array([])
    # total = np.array([])
    # ip_header = np.array([])
    # tcp_header = np.array([])
    # udp_header = np.array([])
    csvfile = open('/Users/kuma/Documents/csc458/proj/458Project/packets.csv')
    # csvfile = open('/Users/Greywolf/Documents/school/CSC/458/packets.csv')
    packets = csv.reader(csvfile)
    tcp, tcp_header = isTCP(packets)
    print(len(tcp), len(tcp_header))
    csvfile.close()
    
    csvfile = open('/Users/kuma/Documents/csc458/proj/458Project/packets.csv')
    packets = csv.reader(csvfile)
    ip, ip_header = isIP(packets)
    print(len(ip), len(ip_header))
    csvfile.close()
    
    csvfile = open('/Users/kuma/Documents/csc458/proj/458Project/packets.csv')
    packets = csv.reader(csvfile)
    udp, udp_header = isUDP(packets)
    print(len(udp), len(udp_header))
    csvfile.close()
    
    csvfile = open('/Users/kuma/Documents/csc458/proj/458Project/packets.csv')
    packets = csv.reader(csvfile)
    nonIP = isNonIP(packets)
    print(len(nonIP))
    csvfile.close()
    # total(packets)
    # # loop through packets
    # for pkt in packets:
    #     # grab the protocol and length of the packet
    #     protocol = pkt[11]
    #     size = pkt[4]
    #     total = np.append(total, size)
    #     if "ip" in protocol or "icmp" in protocol:
    #         # ip packet
    #         ip = np.append(ip,size)
    #         ip_header = np.append(ip_header, pkt[13])
    #     else:
    #         nonIP = np.append(nonIP, size)
    #     if "udp" in protocol:
    #         # udp packet
    #         udp = np.append(udp, size)
    #         udp_header = np.append(udp_header, 8)
    #     if "tcp" in protocol:
    #         tcp = np.append(tcp, size)
    #         tcp_header = np.append(tcp_header, pkt[14])

# print('man si le')
# print(ip)
# plot(ip, 'ip')
# plot(tcp, 'tcp')
# plot(ip_header, 'ip header')
# plot(tcp_header, 'tcp_header')
# plot(udp, 'udp')
# plot(udp_header, 'udp_header')
# plot(total, 'total')
# plot(nonIP, 'nonip')



        
# total = sum(protocols.values())
# for item in protocols:
#     protocols[item] = protocols[item]/float(total)
# f = open("/Users/Greywolf/Documents/school/CSC/458/results.txt", "w")
# f.write(str(protocols))
# f.write(str(total))
    

        