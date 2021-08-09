#!/usr/bin/env python
# coding: utf-8



import pandas as pd
from sklearn.utils import resample


# # Benign



b1 = pd.read_pickle("Pickles/Part 1/Benign1/ddos_part1_benign1.pkl", compression="gzip")
b1 = b1.sort_values("packets", ascending=False)




b1.iloc[15:30,:]




b1 = b1[b1["packets"]>500]
len(b1)




b21 = pd.read_pickle("Pickles/Part 1/Benign2/ddos_part1_benign21.pkl", compression="gzip")
b21 = b21.sort_values("packets", ascending=False)




b21 = b21[b21["packets"]>500]




b22 = pd.read_pickle("Pickles/Part 1/Benign2/ddos_part1_benign22.pkl", compression="gzip")
b22 = b22.sort_values("packets", ascending=False)




b22 = b22[b22["packets"]>500]




b31 = pd.read_pickle("Pickles/Part 1/Benign3/ddos_part1_benign31.pkl", compression="gzip")
b31 = b31.sort_values("packets", ascending=False)




b31 = b31[b31["packets"]>500]




b32 = pd.read_pickle("Pickles/Part 1/Benign3/ddos_part1_benign32.pkl", compression="gzip")
b32 = b32.sort_values("packets", ascending=False)




b32 = b32[b32["packets"]>500]




p2p11 = pd.read_pickle("Pickles/Part 1/P2pbox/ddos_part1_benign_p2pbox11.pkl", compression="gzip")
p2p11 = p2p11.sort_values("packets", ascending=False)




p2p11 = p2p11[p2p11["packets"]>500]




p2p12 = pd.read_pickle("Pickles/Part 1/P2pbox/ddos_part1_benign_p2pbox12.pkl", compression="gzip")
p2p12 = p2p12.sort_values("packets", ascending=False)




p2p12 = p2p12[p2p12["packets"]>500]




b2_1 = pd.DataFrame([],columns=["src", "dst","output","packets","duration","rate","mean","std","max","min", "tcp",                "udp", "dns","icmp","syn", "ack","psh", "fin","urg","rst","sport","dport"])




for i in range(1,7):
    df = pd.read_pickle(f"Pickles/Part 2/Benign/newBenign{i}")
    b2_1 = pd.concat([b2_1,df], ignore_index=True)




b2_1 = b2_1.sort_values("packets", ascending=False)




b2_1 = b2_1[b2_1["packets"]>500]




allbenign = pd.concat([b1, b21, b22, b31, b32, p2p11, p2p12, b2_1])




largebenign = allbenign[allbenign["packets"]>15000]
len(largebenign)




smallbenign = allbenign[allbenign["packets"]<15000]
len(smallbenign)




resampled_smallbenign = resample(smallbenign, n_samples=50, replace=False, random_state=42)




benign = pd.concat([largebenign,resampled_smallbenign])




benign.to_pickle("Benign_resampled.pkl")




len(benign)


# # Attack



attack1 = pd.DataFrame([],columns=["src", "dst","output","packets","duration","rate","mean","std","max","min", "tcp",                "udp", "dns","icmp","syn", "ack","psh", "fin","urg","rst","sport","dport"])
for i in range(1,5):
    df = pd.read_pickle(f"Pickles/Part 1/Attack/ddos_part1_attack{i}.pkl")
    attack1 = pd.concat([attack1,df], ignore_index=True)




for i in range(1,32):
    df = pd.read_pickle(f"Pickles/Part 2/Attack/newDDoS{i}")
    attack1 = pd.concat([attack1,df], ignore_index=True)




attack1.to_pickle("Attack.pkl")


# # Train



train = pd.concat([benign,attack1], ignore_index=True)




train["output"] = (train["output"]!="Benign").astype(int)




train.to_pickle("Train_res.pkl")




y_train = train["output"]




X_train = train.drop(columns=["output"])




X_train.to_pickle("X_train_res.pkl")
y_train.to_pickle("y_train_res.pkl")




X_train.to_csv("X_train_res.csv", index=False)
y_train.to_csv("y_train_res.csv", index=False)




pd.Series(X_train.drop(columns=["src","dst"]).columns).to_csv("features.txt", sep=" ")

