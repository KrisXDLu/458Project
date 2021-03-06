import csv
import numpy as np 
import matplotlib.pyplot as plt
import time
import datetime
import math


def replace_valueA_to_valueB(list, valueA, valueB):
    for idx, item in enumerate(list):
        if item == valueA:
            list[idx] = valueB

def scatter_plot(listX, listY, listY2, title, title1, title2):
    plt.plot(listX, listY)
    plt.plot(listX, listY2)
    plt.title(title)
    plt.legend([title1, title2], loc='upper left')
    plt.grid(True)
    plt.savefig(title)    
    plt.clf()
    
def plot(data, title, log=True):
    if log: data =np.log(data)
    plt.figure()
    plt.hist(data, density=True, histtype='stepfilled', cumulative=True, alpha=0.75, edgecolor = 'black')
    plt.xlabel('Log {}'.format(title[:-9]) if log else '{}'.format(title[:-9]))
    plt.yticks(np.linspace(0,1,11))
    plt.title(title)
    plt.grid(True)
    plt.savefig(title)
    
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
# ACK No,TCP Segment Len, IP Size, Sequence number
# 20      21              22        23
# The RTT, pack asso with ack, Info
#  24          25                26

## for Dataset Statistics below

# Generate a flow dictionary
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


# Get list of counts of packets for each flow
def getType(dictFlow):
    tcp = 0
    udp = 0
    ip = 0
    for flow in dictFlow:
        if "tcp" in dictFlow[flow][0][11]:
            tcp += len(dictFlow[flow])
        if "udp" in dictFlow[flow][0][11]:
            udp += len(dictFlow[flow])
        if "ip" in dictFlow[flow][0][11]:
            ip += len(dictFlow[flow])
    return tcp, udp, ip

#Get list of flow count for all flows/tcp flows/udp flows
def getFlowCount(dictFlow):
    tcp = 0
    udp = 0
    ip = 0
    for flow in dictFlow:
        if "tcp" in dictFlow[flow][0][11]:
            tcp += 1
        if "udp" in dictFlow[flow][0][11]:
            udp += 1
        if "ip" in dictFlow[flow][0][11]:
            ip += 1
    return tcp, udp, ip

#Get list of durations for all flows/ tcp flows / udp flows
def getDuration(dictFlow):
    duration = []
    tcp = []
    udp = []
    for flow in dictFlow:
        first = float(dictFlow[flow][0][1])
        last = float(dictFlow[flow][-1][1])
        time = last - first     
        duration.append(time)   
        if "tcp" in dictFlow[flow][0][11]:
            tcp.append(time)
        if "udp" in dictFlow[flow][0][11]:
            udp.append(time)
    return duration, tcp, udp

# list of flowsize for each flow
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
        if "tcp" in flows[flow][0][11]:
            tcpSize.append(size)
            tcpCount.append(count)
            if float(size) == 0.0:
                ratio.append(9999)
            else:
                ratio.append(header/float(size))
        if "UDP" in flow:
            udpSize.append(size)
            udpCount.append(count)
    return allSize, allCount, tcpSize, tcpCount, udpSize, udpCount, ratio

# Get inter-packet arrival time List for all flows/ tcp flow/udp flow
def interPacketArrival(flows):
    allTime = []
    tcpTime = []
    udpTime = []
    for flow in flows:
        time = []
        pkt = flows[flow]
        
        first = float(pkt[0][1])
        for i in range(1, len(pkt)):
            key = pkt[i][6] + " " + pkt[i][7] + " " + pkt[i][8] + " " + pkt[i][9] + " " + pkt[i][3]
            if key == flow:
               
                time.append(float(pkt[i][1]) - first)
                first = float(pkt[i][1])
            
        allTime += time
        if "tcp" in pkt[0][11]:
            tcpTime += time
        if 'udp' in pkt[0][11]:
            udpTime += time
    return allTime, tcpTime, udpTime

# Get TCP State count for all flows
def getTCPState(flows):
    requested = 0
    reset = 0
    finished = 0
    ongoing = 0
    failed = 0
    total = 0
    for key in flows:
        if "tcp" in flows[key][0][11]:
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
# (66, 4294, 20, 8686, 0, 13066) this is what we get for TCP state

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


## for RTT Estimation below

# Get the largest flow for RTT flow use
def getLargestFlow(flows):
    pktNum = [0, 0, 0]
    byteSize = [0, 0, 0]
    duration = [0, 0, 0]
    resultNum = [[], [], []]
    resultByte = [[], [], []]
    resultDuration = [[], [], []]
    for key in flows:
        if "tcp" in flows[key][0][11]:
            flow = flows[key]
            byte = 0
            for i in range(len(flow)):
                curFlow = flow[i]
                byte += int(curFlow[4])
            dur = float(flow[-1][1]) - float(flow[0][1])
            num = len(flow)
            if num > pktNum[0]:
                pktNum[2] = pktNum[1]
                pktNum[1] = pktNum[0]
                pktNum[0] = num
                resultNum[2] = resultNum[1]
                resultNum[1] = resultNum[0]
                resultNum[0] = flow
            elif num > pktNum[1]:
                pktNum[2] = pktNum[1]
                pktNum[1] = num
                resultNum[2] = resultNum[1]
                resultNum[1] = flow
            elif num > pktNum[2]:
                pktNum[2] = num
                resultNum[2] = flow

            if byte > byteSize[0]:
                byteSize[2] = byteSize[1]
                byteSize[1] = byteSize[0]
                byteSize[0] = byte
                resultByte[2] = resultByte[1]
                resultByte[1] = resultByte[0]
                resultByte[0] = flow
            elif byte > byteSize[1]:
                byteSize[2] = byteSize[1]
                byteSize[1] = byte
                resultByte[2] = resultByte[1]
                resultByte[1] = flow
            elif byte > byteSize[2]:
                byteSize[2] = byte
                resultByte[2] = flow

            if dur > duration[0]:
                duration[2] = duration[1]
                duration[1] = duration[0]
                duration[0] = dur
                resultDuration[2] = resultDuration[1]
                resultDuration[1] = resultDuration[0]
                resultDuration[0] = flow
            elif dur > duration[1]:
                duration[2] = duration[1]
                duration[1] = dur
                resultDuration[2] = resultDuration[1]
                resultDuration[1] = flow
            elif dur > duration[2]:
                duration[2] = dur
                resultDuration[2] = flow
    return resultNum, resultByte, resultDuration          

# generate csv files in order to investigate flows
def generateFlowCSV():
    output = open('/Users/Greywolf/Documents/school/CSC/458/flows.csv', "w")
    wr = csv.writer(output, dialect='excel')
    for flow in flows:
        for line in flows[flow]:
            wr.writerow(line)       
        wr.writerow([])
    output.close()

# generate csv flows with no duplication
def generateFlowNoDup():
    csvFile = open('/Users/Greywolf/Documents/school/CSC/458/rtt.csv')
    packets = csv.reader(csvFile)
    output = open('/Users/Greywolf/Documents/school/CSC/458/tcpflows.csv', "w")

    flows = generateFlow(packets)
    wr = csv.writer(output, dialect='excel')
    for flow in flows:
        for line in flows[flow]:
            wr.writerow(line)       
        wr.writerow([])
    output.close()
    csvFile.close()
    return flows

# get RTT flows estimation plots
def getRTT(flowList,title):
    result = []
    i=1
    for flow in flowList:
        print(calRTT(flow))
        res1, res2 = calRTT(flow)        
        scatter_plot(res1[2],res1[0],res1[1],title+str(i)+'fD','estimateRTTvsTime','sampleRTTvsTime')
        scatter_plot(res2[2],res2[0],res2[1],title+str(i)+'bD','estimateRTTvsTime','sampleRTTvsTime')
        i+=1
    return result


# sample to understand getRTT 
# def getAllRTT(flows):
#     larNum, larSize, LonDur = getLargestFlow(flows)
#     getRTT(larNum)

    
# generate lists of from the 
def calRTT(flow):
    # two direction rtt
    estRTT1 = []
    estRTT2 = []
    time1 = []
    samRTT1 = []
    samRTT2 = []
    time2 = []
    flag = [0,0]
    SRTT1 = 0
    SRTT2 = 0
    source1 = flow[0][6]
    for pkt in flow:
        if pkt[24] != '':
            RTT = float(pkt[24])
            if pkt[6] == source1: 
                if flag[0] == 0:
                    SRTT1 = RTT
                    estRTT1.append(SRTT1)
                    flag[0] = 1
                else:
                    SRTT1 = (1.0 - 1/8.0)*SRTT1 + 1/8.0 * RTT
                    estRTT1.append(SRTT1)
                samRTT1.append(RTT)
                time1.append(float(pkt[1]))
            else:
                if flag[1] == 0:
                    SRTT2 = RTT
                    estRTT2.append(SRTT2)
                    flag[1] = 1
                else:
                    SRTT2 = (1.0 - 1/8.0)*SRTT2 + 1/8.0 * RTT
                    estRTT2.append(SRTT2)
                samRTT2.append(RTT)
                time2.append(float(pkt[1]))
    return [estRTT1, samRTT1, time1], [estRTT2, samRTT2, time2]


def getHighestConnections():
    # csvfile = open('/Users/Greywolf/Documents/school/CSC/458/connections.csv')
    csvfile = open('/Users/kuma/Documents/458Project/connections.csv')
    connections = csv.reader(csvfile)
    hostConnection = {}
    maxConn = [0, 0, 0]
    conList = [[], [], []]
    
    for con in connections:
        key = (con[0], con[2])
        key2 = (con[2], con[0])
        if key in hostConnection:
            hostConnection[key] += 1
        elif key2 in hostConnection:
            hostConnection[key2] += 1
        else:
            hostConnection[key] = 1
    for con in hostConnection:
        num = hostConnection[con]
        if num > maxConn[0]:
            maxConn[2] = maxConn[1]
            maxConn[1] = maxConn[0]
            maxConn[0] = num
            conList[2] = conList[1]
            conList[1] = conList[0]
            conList[0] = con
        elif num > maxConn[1]:
            maxConn[2] = maxConn[1]
            maxConn[1] = num
            conList[2] = conList[1]
            conList[1] = con
        elif num > maxConn[2]:
            maxConn[2] = num
            conList[2] = con
    return conList      

# hosts = [source ip, dest ip]
# flows = {srcip + srcport + desip + desport:[pkts]}
def getHostsFlows(hosts, flows):
    src = hosts[0]
    des = hosts[1]
    #list of flows(a flow is a list of packet) 
    # belong to the pair of hosts
    result = [] 
    for flow in flows:
        if src in flow and des in flow:
            result.append(flows[flow])
    return result

# list of flow for that pair of hosts
def medianRTTStartTime(flows):
    startTime = []
    medianRTT = []
    for flow in flows:
        startTime.append(float(flow[0][1]))
        estRTT = []
        flag = 0
        for pkt in flow:
            if pkt[24] != '':
                RTT = float(pkt[24])
                if flag == 0:
                    SRTT = RTT
                    estRTT.append(SRTT)
                    flag = 1
                else:
                    SRTT = (1.0 - 1/8.0)*SRTT + 1/8.0 * RTT
                    estRTT.append(SRTT)
        median = int(math.floor(len(estRTT)/2))
        medianRTT.append(estRTT[median])
    return startTime, medianRTT


if __name__ == "__main__":   
    #scripts for generating data
    ##MINJIA's plot
    
    ## plot for the Dataset Statistics part
    # csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets)
    # duration, tcp, udp = getDuration(flows)
    # 
    # plot(duration, 'allFlowDuration_CDF_plot')
    # plot(tcp, 'TCPflowDuration_CDF_plot')
    # plot(udp, 'UDPflowDuration_CDF_plot')
    # csvfile.close()
    
    # csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets)
    # allInterPacket, tcpInterPacket, udpInterPacket = interPacketArrival(flows)
    # plot(allInterPacket, 'allInterPacketArrival_CDF_plot')
    # plot(tcpInterPacket, 'tcpInterPacketArrival_CDF_plot')
    # plot(udpInterPacket, 'udpInterPacketArrival_CDF_plot')
    # csvfile.close()

   
    # csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets) 
    # # we have to change size of 0 to 1 to validate log xscale plots
    # replace_valueA_to_valueB(allSize, 0, 1)
    # replace_valueA_to_valueB(tcpSize, 0, 1)
    # replace_valueA_to_valueB(udpSize, 0, 1)
    # plot(allSize, 'allFlowSizes_CDF_plot')
    # plot(tcpSize, 'TCPflowSize_CDF_plot')
    # plot(udpSize, 'UDPflowSize_CDF_plot')
    # csvfile.close()

    # csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets) 
    # plot(ratio, 'TCPoverheadRatio_CDF_plot',False)
    # plot(ratio, 'TCPoverheadRatio_CDF_plot(with log)')
    # csvfile.close()
    
    # csvfile = open('/Users/kuma/Documents/458Project/packets.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets) 
    # allSize, allCount, tcpSize, tcpCount, udpSize, udpCount, ratio = flowSizeCal(flows)
    # print(len(allSize))
    # csvfile.close()
    
## RTT Estimation part
    # csvfile = open('/Users/Greywolf/Documents/school/CSC/458/rtt.csv')
    # csvfile = open('/Users/kuma/Documents/458Project/rtt.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets)
    # a,b,c = getType(flows)
    # print(a,b,c)
    # larNum, larSize, lonDur = getLargestFlow(flows)
    # getRTT(larNum, 'largest3PacketNumber')
    # getRTT(larSize, 'largest3TotalBytesSize')
    # getRTT(lonDur, 'largest3Duration')
    # generateFlowNoDup()
    # csvfile.close()

    # csvfile = open('/Users/Greywolf/Documents/school/CSC/458/rtt.csv')
    # csvfile = open('/Users/kuma/Documents/458Project/rtt.csv')
    # packets = csv.reader(csvfile)
    # flows = generateFlow(packets)
    # hosts = getHighestConnections()
    # i=1
    # for host in hosts:
    #     flowList = getHostsFlows(host, flows)
    #     startT, medianRTT = medianRTTStartTime(flowList)
    #     
    #     print(medianRTT)
    #     # plot here TODO
    #     
    #     plt.plot(startT, medianRTT)
    #     title = "medianRTT_vs_startT_"+str(i)
    #     plt.title(title)
    #     plt.grid(True)
    #     plt.savefig(title)  
    #     plt.clf()
    #     i+=1
    # csvfile.close()
