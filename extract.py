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
    features = {}
    for k in timedict:
        len_std = statistics.pstdev(lendict[k])
        ttl_std = statistics.pstdev(ttldict[k])
        len_mean = statistics.mean(lendict[k])
        ttl_mean = statistics.mean(ttldict[k])
        time_std = statistics.pstdev(timedict[k])
        numPackets = len(timedict[k])
        time_range = max(timedict[k]) - min(timedict[k])
        entry = [numPackets/time_range, time_range, time_std, len_mean, len_std, ttl_mean, ttl_std]
        features[k] = entry

    single_way = []
    for k in features.keys():
        if ((k[1],k[0]) not in features):
            single_way.append((k[1],k[0]))

    for k in single_way:
        features[k] = [None, None, None, None, None, None, None]

    result = []
    for k in features:
        resEntry = [k[0], k[1]]
        resEntry.extend(features[k])
        resEntry.extend(features[k[1],k[0]])
        result.append(resEntry)
    return result

def pcap_data_loader(filename):
    f = open(filename,'rb')
    pcap = dpkt.pcap.Reader(f)
    return parse(pcap)

def pcapng_data_loader(filename):
    f = open(filename,'rb')
    pcap = dpkt.pcapng.Reader(f)
    return parse(pcap)

def main():
    print(pcap_data_loader("error.pcap"))

if __name__ == "__main__":
    main()



