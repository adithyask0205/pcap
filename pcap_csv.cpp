#include <pcap.h>        // For reading pcap files
#include <iostream>      // For printing messages
#include <fstream>       // For file output
#include <netinet/ip.h>  // For IP header stuff
#include <netinet/tcp.h> // For TCP header stuff
#include <arpa/inet.h>   // For IP address conversion
#include <cstring>       // For char array ops
#include <iomanip>       // For output formatting

using namespace std;

// Handles PCAP file processing and CSV generation.
class PacketAnalyzer {
private:
    int totalPacketCount = 0;
    ofstream csvOutputFile;
    static const int ETHERNET_HEADER_SIZE = 14;
    static const int FTP_CONTROL_PORT = 21;
    static const int MAX_COMMAND_LENGTH = 256;

    // Extracts an FTP command, terminated by CRLF, from the payload, into a char array.
    void extractFtpCommand(const u_char* packetData, int offset, int len, char* commandBuffer) {
        commandBuffer[0] = '\0';
        if (len <= 0 || len >= MAX_COMMAND_LENGTH) return;
        const char* payloadStart = reinterpret_cast<const char*>(packetData + offset);
        int commandLength = 0;
        for (int i = 0; i < len - 1; i++) {
            if (payloadStart[i] == '\r' && payloadStart[i + 1] == '\n') {
                commandLength = i;
                break;
            }
        }
        if (commandLength == 0) {
            commandLength = (len < MAX_COMMAND_LENGTH - 1) ? len : MAX_COMMAND_LENGTH - 1;
        }
        strncpy(commandBuffer, payloadStart, commandLength);
        commandBuffer[commandLength] = '\0';
    }

public:
    ~PacketAnalyzer() {
        if (csvOutputFile.is_open()) {
            csvOutputFile.close(); // Ensure file is closed on destruction
        }
    }

    // Open CSV and write header
    bool startCsv(const char* fname) {
        csvOutputFile.open(fname);
        if (!csvOutputFile.is_open()) {
            cerr << "Couldn't create CSV file: " << fname << endl;
            return false;
        }
        csvOutputFile << "frame.number,frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,ftp.request.command" << endl;
        return true;
    }

    // Main packet processing callback for pcap_loop.
    void processPacket(const struct pcap_pkthdr* header, const u_char* packetData) {
        totalPacketCount++;
        // Skip Ethernet header to get IP header
        const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packetData + ETHERNET_HEADER_SIZE);
        if (ipHeader->ip_p != IPPROTO_TCP) return; // Only process TCP packets

        int ipHeaderLength = ipHeader->ip_hl * 4; // IP header length can vary
        // Get TCP header after IP header
        const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(
            packetData + ETHERNET_HEADER_SIZE + ipHeaderLength);

        int sourcePort = ntohs(tcpHeader->th_sport);
        int destinationPort = ntohs(tcpHeader->th_dport);

        char ftpCommand[MAX_COMMAND_LENGTH];
        ftpCommand[0] = '\0';
        int tcpHeaderLength = tcpHeader->th_off * 4; // TCP header length can vary
        int payloadOffset = ETHERNET_HEADER_SIZE + ipHeaderLength + tcpHeaderLength;
        int payloadLength = header->caplen - payloadOffset;

        // Check if this is FTP control traffic and payload exists
        if ((sourcePort == FTP_CONTROL_PORT || destinationPort == FTP_CONTROL_PORT) && payloadLength > 0) {
            extractFtpCommand(packetData, payloadOffset, payloadLength, ftpCommand);
        }

        // Prepare buffers for IP addresses
        char sourceIpAddress[INET_ADDRSTRLEN], destinationIpAddress[INET_ADDRSTRLEN];
        strncpy(sourceIpAddress, inet_ntoa(ipHeader->ip_src), INET_ADDRSTRLEN - 1);
        sourceIpAddress[INET_ADDRSTRLEN - 1] = '\0';
        strncpy(destinationIpAddress, inet_ntoa(ipHeader->ip_dst), INET_ADDRSTRLEN - 1);
        destinationIpAddress[INET_ADDRSTRLEN - 1] = '\0';

        // Combine seconds and microseconds for timestamp
        double packetTimestamp = static_cast<double>(header->ts.tv_sec) + static_cast<double>(header->ts.tv_usec) / 1000000.0;

        // Write all extracted fields to CSV
        csvOutputFile << totalPacketCount << "," << fixed << setprecision(6) << packetTimestamp << ","
                      << sourceIpAddress << "," << destinationIpAddress << ","
                      << sourcePort << "," << destinationPort << "," << '"' << ftpCommand << '"' << endl;
    }

    // Opens a PCAP file and processes all packets.
    bool processPcapFile(const char* pcapFilename, const char* csvFilename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(pcapFilename, errbuf);
        if (handle == nullptr) {
            cerr << "Error opening PCAP file: " << errbuf << endl;
            return false;
        }

        if (!startCsv(csvFilename)) {
            pcap_close(handle);
            return false;
        }

        // Use a lambda as the pcap_loop callback to call the member function
        pcap_loop(handle, 0, [](u_char* userData, const struct pcap_pkthdr* h, const u_char* p) {
            reinterpret_cast<PacketAnalyzer*>(userData)->processPacket(h, p);
        }, reinterpret_cast<u_char*>(this));
        
        pcap_close(handle);
        return true;
    }

    int getTotalPacketCount() const {
        return totalPacketCount;
    }
};

int main() {
    const char* inputPcapFile = "ftp.pcap";
    const char* outputCsvFile = "ftp_packets.csv";
    PacketAnalyzer analyzer;

    // Process the PCAP file and write results to CSV
    if (analyzer.processPcapFile(inputPcapFile, outputCsvFile)) {
        cout << "Processing completed. Output saved to: " << outputCsvFile << endl;
        cout << "Total packets processed: " << analyzer.getTotalPacketCount() << endl;
    } else {
        cerr << "Error: Processing failed." << endl;
        return 1;
    }
    return 0;
}