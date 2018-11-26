import csv
import numpy as np 
import matplotlib.pyplot as plt
import time
import datetime
import math
import os


# arr = np.random.normal(size=100)
# 
# plt.subplot(121)
# hist, bin_edges = np.histogram(arr)
# cdf = np.cumsum(hist)
# plt.plot(cdf)
# 
# plt.subplot(122)
# cdf = stats.cumfreq(arr)
# plt.plot(cdf[0])
# 
# plt.show()

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
def plot(data, title, log=True):
    
    if log: data = [np.log(i) for i in data]
    plt.figure()
    plt.hist(data, density=True, histtype='stepfilled', cumulative=True, alpha=0.75, edgecolor = 'black')
    plt.xlabel('Log {} (Bytes)'.format(title[:-9]) if log else '{} (Bytes)'.format(title[:-9]))
    plt.yticks(np.linspace(0,1,11))
    plt.title(title)
    plt.grid(True)
    plt.savefig(title)

def total(packets):
    total = []
    for pkt in packets:
        protocol = pkt[11]
        if pkt[4].isnumeric():
            total.append(int(pkt[4]))
    return total

def isIP(packets):
    ip = []
    ip_header = []
    for pkt in packets:
        protocol = pkt[11]
        if pkt[13].isnumeric() and ('ip' in protocol or 'icmp' in protocol):
            ip.append(int(pkt[4]))
            ip_header.append(int(pkt[13]))
    return ip, ip_header
    
def isNonIP(packets):
    nonIp = []
    for pkt in packets:
        protocol = pkt[11]
        if pkt[4].isnumeric() and ('ip' not in protocol) and ('icmp' not in protocol):
            nonIp.append(int(pkt[4]))
    return nonIp

def isTCP(packets):
    tcp = []
    tcp_header = []
    for pkt in packets:
        protocol = pkt[11]
        if 'tcp' in protocol:
            tcp.append(int(pkt[4]))
            tcp_header.append(int(pkt[14]))
    return tcp, tcp_header
    
def isUDP(packets):
    udp = []
    udp_header = []
    for pkt in packets:
        protocol = pkt[11]
        if pkt[4].isnumeric() and 'udp' in protocol:
            udp.append(int(pkt[4]))
    return udp, udp_header

if __name__ == "__main__":   
    ip = np.array([])
    udp = np.array([])
    tcp = np.array([])
    nonIP = np.array([])
    total = np.array([])
    ip_header = np.array([])
    tcp_header = np.array([])
    udp_header = np.array([])

    csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    # csvfile = open('/Users/Greywolf/Documents/school/CSC/458/packets.csv')
    packets = csv.reader(csvfile)
    tcp, tcp_header = isTCP(packets)
    csvfile.close()
    plot(tcp, 'tcp_packetsize_CDF_plot')
    plot(tcp_header, 'tcpHeader_size_CDF_plot')
    
    csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    packets = csv.reader(csvfile)
    ip, ip_header = isIP(packets)
    csvfile.close()
    plot(ip, 'IP_packetsize_CDF_plot')
    plot(ip_header, 'IPheader_size_CDF_plot')
    
    csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    packets = csv.reader(csvfile)
    udp, udp_header = isUDP(packets)
    csvfile.close()
    plot(udp, 'UDP_packetsize_CDF_plot')
    plot(udp_header, 'UDPheader_size_CDF_plot')
    
    csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    packets = csv.reader(csvfile)
    nonIP = isNonIP(packets)
    csvfile.close()
    plot(nonIP, 'non-IP_packetsize_CDF_plot')
    
    
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
    

        