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

def flow(packets):
    dic_flow = {}
    for pkt in packets:
        key = pkt[6] + " " + pkt[7] + " " + pkt[8] + " " + pkt[9] + " " + pkt[3]
        if key in dic_flow:
            dic_flow[key].append(pkt)
        else:
            dic_flow[key] = [pkt
    return dic_flow

def packetsNum(dictFlow):
    tcp = []
    udp = []
    for item in dictFlow:
        if "TCP" == dictFlow[item][3]:
            

if __name__ == "__main__":   
    csvfile = open('/Users/Greywolf/Documents/school/CSC/458/packets.csv')
    packets = csv.reader(csvfile)
    

    dic_keys = dic_flow.keys()
    for key in dic_flow.keys():
        pktList = dic_flow[key]
        firstT = int(packets["Arrival Time"][pktList[0]])
        for i in range(len(pktList), -1, -1):
            cur = int(packets["Arrival Time"][i])
            # not valid since small trace file
            # if cur > (90*60 + firstT):
            #     # add new flow for packets later than 90min
            #     key2 = key  + " 2"  
            #     if key2 in dic_flow: 
            #         dic_flow[key2] = [dic_flow[key].pop()]
            #         dic_keys.append(key2)
            #     else:
            #         dic_flow[key2].insert(0, dic_flow[key].pop())


