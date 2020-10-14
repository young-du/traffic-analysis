import dpkt
import socket

def printPcap(pcap):
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            print ("Source: " +src+ " Destination: "  +dst)
            print (tcp.sport, tcp.dport)

        except:
            pass

def main():
    # Open pcap file for reading
    f = open("error.pcap",'rb')
    #pass the file argument to the pcap.Reader function
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == "__main__":
    main()