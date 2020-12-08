''' use "pcap_data_loader" or "pcapng_data_loader" to load data
    each row of data looks like:
    [
        source, destination, 
        (sending) numPackets per unit time, time range, timestamp_std, packet_length_mean, packet_length_std, time_to_live_mean, time_to_live_std,
        (receiving) numPackets per unit time, time range, timestamp_std, packet_length_mean, packet_length_std, time_to_live_mean, time_to_live_std
    ]
    if the trace is ONE-WAY, entries will be None.
    
    (std means standart deviation)
'''

import dpkt
import socket
from collections import defaultdict
import statistics

def dv():
    return []

def parse(pcap):
    timedict = defaultdict(dv)
    lendict = defaultdict(dv)
    ttldict = defaultdict(dv)
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data       
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            timedict[(src, dst)].append(ts)
            lendict[(src, dst)].append(ip.len)
            ttldict[(src, dst)].append(ip.ttl)
        except:
            pass
    features = []
    for k in timedict:
        len_std = statistics.pstdev(lendict[k])
        ttl_std = statistics.pstdev(ttldict[k])
        len_mean = statistics.mean(lendict[k])
        ttl_mean = statistics.mean(ttldict[k])
        time_std = statistics.pstdev(timedict[k])
        numPackets = len(timedict[k])
        time_range = max(timedict[k]) - min(timedict[k])
        if time_range != 0:
            entry = [numPackets/time_range, time_range, time_std, len_mean, len_std, ttl_mean, ttl_std]
            features.append(entry)

    return features

def pcap_data_loader(filename):
    f = open(filename,'rb')
    pcap = dpkt.pcap.Reader(f)
    return parse(pcap)

def pcapng_data_loader(filename):
    f = open(filename,'rb')
    pcap = dpkt.pcapng.Reader(f)
    return parse(pcap)





