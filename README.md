# PCAP

This repository contains C++ programs for analyzing and processing network packet capture (PCAP) files, focusing on TCP and FTP traffic.

## File Descriptions

- **ftp.pcap**: Sample packet capture file containing network traffic (used as input for all programs).
- **pcap_reader.cpp**: Reads a PCAP file and prints TCP packet source/destination IPs and ports to the console.
- **pcap_csv.cpp**: Reads a PCAP file, extracts TCP and FTP command information, and writes detailed results to a CSV file.
- **pcap_pnc.cpp**: Tackles producer-consumer problem occured while processing a PCAP file and writing packet summaries to a CSV file.

## Requirements

- **libpcap** development headers and library (e.g., `libpcap-dev` on Linux)
- **g++** or another C++ compiler
- For `pcap_pnc.cpp`, POSIX threads (pthreads) are required (usually included by default on Linux)

## How to Compile

Open a terminal in this folder and use the following commands:

### 1. Compile `pcap_reader.cpp`
```
g++ -o pcap_reader pcap_reader.cpp -lpcap
```

### 2. Compile `pcap_csv.cpp`
```
g++ -o pcap_csv pcap_csv.cpp -lpcap
```

### 3. Compile `pcap_pnc.cpp` (with pthreads)
```
g++ -o pcap_pnc pcap_pnc.cpp -lpcap -lpthread
```

## How to Run

Make sure `ftp.pcap` is present in the same directory. Each program expects this file as input.

### 1. Run `pcap_reader`
```
./pcap_reader
```
- **Output:** Prints TCP packet source/destination IPs and ports to the terminal.

### 2. Run `pcap_csv`
```
./pcap_csv
```
- **Output:** Creates `packets.csv` with detailed TCP and FTP command information for each packet.

### 3. Run `pcap_pnc`
```
./pcap_pnc
```
- **Output:** Creates `packets.csv` with a summary of each packet using a multi-threaded approach.

## Notes
- All programs assume the input file is named `ftp.pcap` and is in the current directory.
- Output CSV files will be overwritten if they already exist.
