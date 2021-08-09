#!/usr/bin/env python
# coding: utf-8



import os
from os.path import join
from pathlib import PurePath
import sys
from scapy.all import rdpcap
import scapy.layers.l2
import pandas as pd
import numpy as np



# Features are extracted partially by the folder given in the data
# Output pickle file names are used in 2. data selection.py file

path = "Ddos_Detection_Dataset/Ddos_Attack_data/3"  # Path to folder
output = "DDoS"  # "Benign" or "DDoS"
outputfile = "ddos_part1_attack3.pkl"   # Output pickle file name




def ftextract(path, output, file):
    
    ########################################### Part 1 ###########################################
    print(f"File: {file} openning...")
    cap = rdpcap(path)
    print(f"File {file} opened...")
    print(f"File has {len(cap)} packets")
    ##############################################################################################
    
    
    
    ######################################### Part 2 ##############################################
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    i = 0

    srcl, dstl, timel, dtl, tcpl, udpl, dnsl, icmpl, lengthl, sportl, dportl, synl, ackl, pshl, finl        , urgl, rstl = ([] for i in range(17))

    for pkt in cap:
        src, dst, time, dt, tcp, udp, dns, icmp, length, sport, dport, fin, syn, rst, psh, ack, urg =             (0 for i in range(17))
        if type(pkt) != scapy.layers.l2.Ether or (not pkt.haslayer("IP")):
            i += 1
            continue
        else:
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            time = float(pkt.time)
            if i>0:
                dt = float(cap[i].time - cap[i-1].time)
            if pkt.haslayer("UDP"):
                udp = 1
                sport = pkt["UDP"].sport
                dport = pkt["UDP"].dport
            else:
                udp = 0
            if pkt.haslayer("TCP"):
                tcp = 1
                sport = pkt["TCP"].sport
                dport = pkt["TCP"].dport
                flag = pkt["TCP"].flags
                if flag & FIN:
                    fin = 1
                if flag & SYN:
                    syn = 1
                if flag & RST:
                    rst = 1
                if flag & PSH:
                    psh = 1
                if flag & ACK:
                    ack = 1
                if flag & URG:
                    urg = 1
            else:
                tcp = 0
            if pkt.haslayer("ICMP"):
                icmp = 1
            else:
                icmp = 0
            if pkt.haslayer("DNS"):
                dns = 1
            else:
                dns = 0
            length = pkt["IP"].len - pkt["IP"].ihl
        srcl.append(src)
        dstl.append(dst)
        timel.append(time)
        dtl.append(dt)
        tcpl.append(tcp)
        udpl.append(udp)
        dnsl.append(dns)
        icmpl.append(icmp)
        lengthl.append(length)
        sportl.append(sport)
        dportl.append(dport)
        synl.append(syn)
        ackl.append(ack)
        pshl.append(psh)
        finl.append(fin)
        urgl.append(urg)
        rstl.append(rst)
        i += 1
    print("Primary DataFrame generated")
    del(cap)
    ##############################################################################################
    
    
    
    
    ########################################### Part 3 ############################################
    df = pd.DataFrame({"src": srcl,"dst":dstl, "time":timel, "dt":dtl, "tcp":tcpl, "udp":udpl, "dns":dnsl, "icmp":icmpl,               "length":lengthl, "sport":sportl, "dport":dportl, "syn":synl, "ack":ackl,               "psh":pshl, "fin":finl, "urg":urgl, "rst":rstl})
    host = df.groupby("dst").apply(len).idxmax()
    src, dst, outputl, pckts, duration, rate, pmean, pstd, pmax, pmin, tcp, udp, dns, icmp, syn, ack, psh, fin, urg,        rst, sport, dport = ([] for i in range(22))

    for name,group in df.groupby(["src","dst"]):

        count = len(group)
        if count<50:
            continue
        if output!="Benign" and len(group)<0.1*len(df):
            continue

        src.append(name[0])
        dst.append(name[1])
        dur = sum(group["dt"])
        pckts.append(count)
        duration.append(dur)

        if output=="Benign":
            outputl.append("Benign")
        elif count < 5000:
            outputl.append("Benign")
        else:
            outputl.append("DDoS")

        rate.append(count/dur)

        pmean.append(group["length"].mean())
        pstd.append(group["length"].std())
        pmax.append(group["length"].max())
        pmin.append(group["length"].min())

        tcpcount = sum(group["tcp"])
        tcp.append(tcpcount)
        udp.append(sum(group["udp"]))
        dns.append(sum(group["dns"]))
        icmp.append(sum(group["icmp"]))

        if tcpcount:
            syn.append(sum(group["syn"])/tcpcount)
            ack.append(sum(group["ack"])/tcpcount)
            psh.append(sum(group["psh"])/tcpcount)
            fin.append(sum(group["fin"])/tcpcount)
            urg.append(sum(group["urg"])/tcpcount)
            rst.append(sum(group["rst"])/tcpcount)
        else:
            syn.append(0)
            ack.append(0)
            psh.append(0)
            fin.append(0)
            urg.append(0)
            rst.append(0)

        sport.append(sum(group["sport"])/count)
        dport.append(sum(group["dport"])/count)
    df2 = pd.DataFrame({"src":src, "dst":dst,"output":output,"packets":pckts,"duration":duration,"rate":rate,                        "mean":pmean,"std":pstd,"max":pmax,"min":pmin, "tcp":tcp, "udp":udp, "dns":dns,"icmp":icmp,                        "syn":syn, "ack":ack,"psh":psh, "fin":fin,"urg":urg,"rst":rst,"sport":sport,"dport":dport})
    ##############################################################################################
    
    return df2




total_files = 0
i = 1
count = 0
data = pd.DataFrame([],columns=["src", "dst","output","packets","duration","rate","mean","std","max","min", "tcp",                "udp", "dns","icmp","syn", "ack","psh", "fin","urg","rst","sport","dport"])
for root, dirs, files in os.walk(path):
    if not len(files):
        continue
    total_files += len(files)
    for file in files:
        df = ftextract(join(root,file), output, file)
        data = pd.concat([data,df],ignore_index=True)
        print(f"File: {file} completed")
        print(f"Progress: {i}/{total_files}")
        i += 1
print(f"Total: {total_files} files processed successfully!")




data




data.to_pickle(outputfile)


# ## Progress

# ### 1
# Path: "Ddos_Detection_Dataset/Ddos_benign/benign1"  
# Pickle: "ddos_part1_benign1.pkl" compression="gzip  
# Rows: 1153  
# Output:  
# File: 1.pcap openning...  
# File 1.pcap opened...  
# File has 753028 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 1.pcap completed  
# File: 2.pcap openning...  
# File 2.pcap opened...  
# File has 784675 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 2.pcap completed  
# File: 3.pcap openning...  
# File 3.pcap opened...  
# File has 771964 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 3.pcap completed  
# File: 4.pcap openning...  
# File 4.pcap opened...  
# File has 846271 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 4.pcap completed  
# File: 5.pcap openning...  
# File 5.pcap opened...  
# File has 1094975 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 5.pcap completed  
# File: 6.pcap openning...  
# File 6.pcap opened...  
# File has 1067183 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 6.pcap completed  
# File: 7.pcap openning...  
# File 7.pcap opened...  
# File has 978170 packets  
# Primary DataFrame generated  
# Host IP: 97.81.96.137  
# File: 7.pcap completed  
# Progress: 1/7  
# Total: 7 files processed successfully!  

# ### 2
# Path: "Ddos_Detection_Dataset/Ddos_benign/benign2/benign21"  
# Pickle:"ddos_part1_benign21.pkl" compression="gzip"  
# Rows: 1229  

# ### 3
# Path: "Ddos_Detection_Dataset/Ddos_benign/benign2/benign22"  
# Pickle:"ddos_part1_benign22.pkl" compression="gzip"  
# Rows: 2115

# ### 4
# Path: "Ddos_Detection_Dataset/Ddos_benign/benign3/benign31"  
# Pickle:"ddos_part1_benign31.pkl" compression="gzip"  
# Rows: 1041

# ### 5
# Path: "Ddos_Detection_Dataset/Ddos_benign/benign3/benign32"  
# Pickle:"ddos_part1_benign32.pkl" compression="gzip"  
# Rows: 1543

# ### 6
# Path: "Ddos_Detection_Dataset/Ddos_benign/p2pbox1/p2pbox11"  
# Pickle:"ddos_part1_benign_p2pbox11.pkl" compression="gzip"  
# Rows: 977

# ### 7
# Path: "Ddos_Detection_Dataset/Ddos_benign/p2pbox1/p2pbox12"  
# Pickle:"ddos_part1_benign_p2pbox12.pkl" compression="gzip"  
# Rows: 1703

# ### 8
# Path: "Ddos_Detection_Dataset/Ddos_Attack_data/1"  
# Pickle:"ddos_part1_attack1.pkl" compression="gzip"  
# Rows: 14

# ### 9
# Path: "Ddos_Detection_Dataset/Ddos_Attack_data/2"  
# Pickle:"ddos_part1_attack2.pkl" compression="gzip"  
# Rows: 28

# ### 10
# Path: "Ddos_Detection_Dataset/Ddos_Attack_data/3"  
# Pickle:"ddos_part1_attack3.pkl" compression="gzip"  
# Rows: 14





