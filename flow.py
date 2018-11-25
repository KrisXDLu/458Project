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
# ACK No,TCP Segment Len, IP Size, Info
# 20      21              22        23

def generateFlow(packets):
    dic_flow = {}
    for pkt in packets:
        key = pkt[6] + " " + pkt[7] + " " + pkt[8] + " " + pkt[9] + " " + pkt[3]
        key2 = pkt[7] + " "  + pkt[6] + " " + pkt[9] + " " + pkt[8] + " " + pkt[3]
        if key in dic_flow:
            dic_flow[key].append(pkt)
        elif key2 in dic_flow:
            dic_flow[key2].append(pkt)
        else:
            dic_flow[key] = [pkt]
    return dic_flow

def getType(dictFlow):
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

def getDuration(dictFlow):
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
    ratio = []
    for flow in flows:
        size = 0
        header = 0
        for pkt in flows[flow]:
            if ',' in pkt[4] + pkt[22] + pkt[13] + pkt[14]:
                break
            size += int(pkt[4]) 
            if pkt[14] != "":
                header += int(pkt[4]) - int(pkt[22]) + int(pkt[13]) + int(pkt[14])
        count = len(flows[flow])
        allSize.append(size)
        allCount.append(count)
        if "TCP" in flow:
            tcpSize.append(size)
            tcpCount.append(count)
            ratio.append(header/float(size))
        if "UDP" in flow:
            udpSize.append(size)
            udpCount.append(count)
    return allSize, allCount, tcpSize, tcpCount, udpSize, udpCount, ratio

def interPacketArrival(flows):
    allTime = []
    tcpTime = []
    udpTime = []
    for flow in flows:
        time = []
        pkt = flows[flow]
        # print(pkt[0][6] + " " + pkt[0][7] + " " + pkt[0][8] + " " + pkt[0][9] + " " + pkt[0][3], flow)
        first = float(pkt[0][1])
        for i in range(1, len(pkt)):
            key = pkt[i][6] + " " + pkt[i][7] + " " + pkt[i][8] + " " + pkt[i][9] + " " + pkt[i][3]
            if key == flow:
                if float(pkt[i][1]) - first == 278.157092:
                    print(pkt)
                time.append(float(pkt[i][1]) - first)
                first = float(pkt[i][1])
            
        allTime += time
        if 'TCP' in flow:
            tcpTime += time
        if 'UDP' in flow:
            udpTime += time
    print(max(allTime))
    return allTime, tcpTime, udpTime

def getTCPState(flows):
    requested = 0
    reset = 0
    finished = 0
    ongoing = 0
    failed = 0
    total = 0
    for key in flows:
        if 'TCP' in key:
            total += 1
            flow = flows[key]
            if isRequest(flow):
                requested += 1
            elif isReset(flow):
                reset += 1
            elif isFinished(flow):
                finished += 1
            elif isOngoing(flow):
                ongoing += 1
            else:
                failed += 1
    return requested, reset, finished, ongoing, failed, total
# (56, 4292, 20, 7514, 0, 11882)

def isRequest(flow):
    return flow[0][16] == 'Set' and len(flow) == 1

def isReset(flow):
    return flow[-1][19] == 'Set'

def isFinished(flow):
    if len(flow) <= 4:
        return False
    # print(flow[-4:])
    if flow[-4][18] != 'Set':
        return False 
    pkt = flow[-1]
    pkt1 = flow[-4]
    key = pkt[6] + " " + pkt[7] + " " + pkt[8] + " " + pkt[9] + " " + pkt[3]
    key1 = pkt1[7] + " "  + pkt1[6] + " " + pkt1[9] + " " + pkt1[8] + " " + pkt1[3]
    if not (key == key1 and pkt[17] == 'Set'):
        return False
    pkt = flow[-3]
    pkt1 = flow[-2]
    if not (pkt[6] + " " + pkt[7] + " " + pkt[8] + " " 
                + pkt[9] + " " + pkt[3] ==  pkt1[7] + " "  + 
                pkt1[6] + " " + pkt1[9] + " " + pkt1[8] + " " + pkt1[3]
                and pkt[17] == 'Set'):
        return False
    if pkt1[18] != 'Set':
        return False   
    return True

def isOngoing(flow):
    return not (isRequest(flow) or isReset(flow) or isFinished(flow))

def flowType(flows):
    tcp, udp, ip = getType(flows)
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
    duration, tcp, udp = getDuration(flows)
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

def flowSizeOutput(flows):
    allSize, allCount, tcpSize, tcpCount, udpSize, udpCount, ratio = flowSizeCal(flows)
    fpt = open('/Users/Greywolf/Documents/school/CSC/458/project/flowSize.txt', "w")
    fpt.write("Total size\n")
    fpt.write(str(allSize))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("All Count\n")
    fpt.write(str(allCount))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("tcpSize\n")
    fpt.write(str(tcpSize))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("tcpCount\n")
    fpt.write(str(tcpCount))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("UDPSize\n")
    fpt.write(str(udpSize))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("UDP Count\n")
    fpt.write(str(udpCount))
    fpt.write("\n")
    fpt.write("\n")
    fpt.write("Ratio\n")
    fpt.write(str(ratio))
    fpt.close()

if __name__ == "__main__":   
    csvfile = open('/Users/Greywolf/Documents/school/CSC/458/packets.csv')
    packets = csv.reader(csvfile)
    flows = generateFlow(packets)

#     # flowtype
#     flowType(flows)
# # duration
#     flowDuration(flows)

#     flowSizeOutput(flows)
    # interPacketArrival(flows)
    print(getTCPState(flows))