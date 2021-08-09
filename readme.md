# DDOS attack Detection

Team: DU_Apophis
Project (Ddos attack Detection)

## Codes
There are four .py files: 
1. `Feature Extraction.py`: includes all the codes for feature extraction
2. `Data Selection.py`: selects the data for training
3. `Train.py`: trains the model.
4. `ddosdetect.py`: the command line tool to detect ddos attack

First three files are training files. `ddosdetect.py` is the main tool.

## How to Use
Run the `ddosdetect.py` in the command line with the path of the pcap file.  
```
	python3 ddosdetect.py absolute_path_for_pcap_file
```
The program will generate a `Prediction.txt` file with source (`src`), 
destination (`dst`) and prediction (`malicious` or `benign`).

## Libraries 
- `python 3.7`
- `scapy - 2.4.3`
- `sklearn - 0.23.1`
- `numpy - 1.19.0`
- `pandas - 1.1.0`
- `os`
- `pathlib`
- `sys`
- `pickle`


## Resources 
The code uses some resources to train the model. These are pre-processed datasets ready to be trained.  
- `X_train.csv`  
- `y_train.csv`  



## Features 
The features we extracted are listed in `features.txt` file