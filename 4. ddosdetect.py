#!/usr/bin/env python
# coding: utf-8




from scapy.all import rdpcap
import scapy.layers.l2
import pandas as pd
import numpy as np
import sys
import os
from sklearn.ensemble import RandomForestClassifier as RFC
from sklearn.neighbors import KNeighborsClassifier as KNN
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.svm import SVC

pd.set_option("mode.chained_assignment", None)




if __name__ == "__main__":
    if len(sys.argv)>1:
        try:
            idx = sys.argv.index("ddosdetect.py")
            if len(sys.argv) > idx+1:
                path = sys.argv[idx+1]
            else:
                print("No path given!")
                sys.exit()
        except:
            path = sys.argv[1]
    else:
        print("No path given!")
        sys.exit()




def ftextract(path):
    
    ########################################### Part 1 ###########################################
    print("File is opening... It will take some moments...")
    try:
        cap = rdpcap(path)
    except:
        raise Exception("Given path is not a valid pcap file!")
    print("Extracting Features...")
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
    del(cap)
    ##############################################################################################
    
    
    
    
    ########################################### Part 3 ############################################
    df = pd.DataFrame({"src": srcl,"dst":dstl, "time":timel, "dt":dtl, "tcp":tcpl, "udp":udpl, "dns":dnsl, "icmp":icmpl,               "length":lengthl, "sport":sportl, "dport":dportl, "syn":synl, "ack":ackl,               "psh":pshl, "fin":finl, "urg":urgl, "rst":rstl})
    host = df.groupby("dst").apply(len).idxmax()
    src, dst, pckts, duration, rate, pmean, pstd, pmax, pmin, tcp, udp, dns, icmp, syn, ack, psh, fin, urg,        rst, sport, dport = ([] for i in range(21))

    for name,group in df.groupby(["src","dst"]):

        count = len(group)
        if count<2:
            continue

        src.append(name[0])
        dst.append(name[1])
        dur = sum(group["dt"])
        pckts.append(count)
        duration.append(dur)

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
    df2 = pd.DataFrame({"src":src, "dst":dst,"packets":pckts,"duration":duration,"rate":rate,                        "mean":pmean,"std":pstd,"max":pmax,"min":pmin, "tcp":tcp, "udp":udp, "dns":dns,"icmp":icmp,                        "syn":syn, "ack":ack,"psh":psh, "fin":fin,"urg":urg,"rst":rst,"sport":sport,"dport":dport})
    ##############################################################################################
    
    return df2




df = ftextract(path)




X_train = pd.read_csv("X_train.csv")
y = pd.read_csv("y_train.csv")
y = y["output"]
names = X_train[["src","dst"]]
X = X_train.drop(columns = ["src", "dst"])





X_train , X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 100, stratify=y)
model = RFC()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

print("Training accuracy:", accuracy_score(y_test,y_pred))





result = df[["src","dst"]]
X_predict = df.drop(columns = ["src", "dst"])
y_predict = model.predict(X_predict)




prediction = []
for i in y_predict:
    if i==1:
        prediction.append("malicious")
    else:
        prediction.append("benign")




result["prediction"] = prediction




result.to_csv("Prediction.txt", index=False)
print()
print("Prediction file is saved as 'Prediction.txt' in the path of this program")

