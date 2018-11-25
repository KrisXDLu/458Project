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

def generateFlow(packets):
    dic_flow = {}
    for pkt in packets:
        key = pkt[6] + " " + pkt[7] + " " + pkt[8] + " " + pkt[9] + " " + pkt[3]
        if key in dic_flow:
            dic_flow[key].append(pkt)
        else:
            dic_flow[key] = [pkt]
    return dic_flow

def packetsNum(dictFlow):
    tcp = 0
    udp = 0
    ip = 0
    for flow in dictFlow:
        if "TCP" in flow:
            tcp += len(dictFlow[flow])
        if "UDP" in flow:
            udp += len(dictFlow[flow])
        if "ip" in dictFlow[flow][0][11]:
            ip += len(dictFlow[flow])
    return tcp, udp, ip

def calDuration(dictFlow):
    duration = []
    tcp = []
    udp = []
    for flow in dictFlow:
        first = float(dictFlow[flow][0][1])
        last = float(dictFlow[flow][-1][1])
        time = last - first     
        duration.append(time)   
        if "TCP" in flow:
            tcp.append(time)
        if "UDP" in flow:
            udp.append(time)
    return duration, tcp, udp

def flowSizeCal(flows):
    allSize = []
    allCount = []
    tcpSize = []
    tcpCount = []
    udpSize = []
    udpCount = []
    for flow in flows:
        size = 0
        for pkt in flows[flow]:
            size += int(pkt[4]) 
        count = len(flows[flow])
        allSize.append(size)
        allCount.append(count)
        if "TCP" in flow:
            tcpSize.append(size)
            tcpCount.append(count)
        if "UDP" in flow:
            udpSize.append(size)
            udpCount.append(count)


def flowType(flows):
    tcp, udp, ip = packetsNum(flows)
    fpt = open('/Users/Greywolf/Documents/school/CSC/458/project/flowType.txt', "w")
    fpt.write("tcp\n")
    fpt.write(str(tcp))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("udp\n")
    fpt.write(str(udp))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("ip\n")
    fpt.write(str(ip))
    fpt.close()

def flowDuration(flows):
# # duration
    duration, tcp, udp = calDuration(flows)
    fpt = open('/Users/Greywolf/Documents/school/CSC/458/project/flowDuration.txt', "w")
    fpt.write("Total flow\n")
    fpt.write(str(duration))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("TCP\n")
    fpt.write(str(tcp))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("UDP\n")
    fpt.write(str(udp))
    fpt.close()


if __name__ == "__main__":   
    csvfile = open('/Users/Greywolf/Documents/school/CSC/458/packets.csv')
    packets = csv.reader(csvfile)
    flows = generateFlow(packets)

    # # flowtype
#     flowType(flows)
# # duration
#     flowDuration(flows)

