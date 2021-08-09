# DDOS Attack Detection with Machine Learning

## Summary
This project analyzes packet capture file to detect any DDoS attack. You can get packet capture files with Wireshark or other softwares.  


This project is made as a solution to the competition [HCL HACK IITK 2020](https://hackathon.iitk.ac.in/).
This goal of this hackathon is to apply the machine learning alogorithms to cyber security technologies.  
  
The data for this competition can be found at [Google Drive](https://drive.google.com/drive/folders/1-MPTCaLIVdW0DOb7RU0r4r7-3gV7Va9v?usp=sharing)  

## Team Info
Team Name: **DU_Apophis**  
Members:
- Shahamat Tasin
- A.H.M. Nazmus Sakib 
- Promit Basak
  

## Codes
There are four .py files: 
1. `Feature Extraction.py`: includes all the codes for feature extraction
2. `Data Selection.py`: selects the data for training
3. `Train.py`: trains the model.
4. `ddosdetect.py`: the command line tool to detect ddos attack

First three files are training files. As I have included the pretrained data here, you may not need to run the first three files.  
`ddosdetect.py` is the main tool. You can use this on any packet capture file.

## How to Use
Run the `ddosdetect.py` in the command line with the path of the pcap (packet capture) file.    
```
	python3 ddosdetect.py path_to_the_pcap_file
```
The program will generate a `Prediction.txt` file with source (`src`), 
destination (`dst`) and prediction (`malicious` or `benign`).

## Libraries 
- `python 3.7`
- `scapy - 2.4.3`
- `sklearn - 0.23.1`
- `numpy - 1.19.0`
- `pandas - 1.1.0`
- `pathlib`


## Resources 
The code uses some resources to train the model. These are pre-processed datasets ready to be trained.  
- `X_train.csv`  
- `y_train.csv`  



## Features 
The features we extracted are listed in `features.txt` file