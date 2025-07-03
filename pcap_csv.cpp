#include <pcap.h>
#include <iostream>
#include <fstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>

using namespace std;

int packetCount = 0;
ofstream csvFile;

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    packetCount++;

    const struct ip* ip_hdr = (struct ip*)(packet + 14);
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    string src_ip = inet_ntoa(ip_hdr->ip_src);
    string dst_ip = inet_ntoa(ip_hdr->ip_dst);

    int ip_header_len = ip_hdr->ip_hl * 4;
    const struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + ip_header_len);

    int src_port = ntohs(tcp_hdr->th_sport);
    int dst_port = ntohs(tcp_hdr->th_dport);

    string ftp_command = "";
    int tcp_header_len = tcp_hdr->th_off * 4;
    int payload_offset = 14 + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - payload_offset;

    if ((src_port == 21 || dst_port == 21) && payload_len > 0) {
        const char* payload = (const char*)(packet + payload_offset);
        string data(payload, payload + payload_len);
        size_t end = data.find("\r\n");
        ftp_command = (end != string::npos) ? data.substr(0, end) : data;
    }

    double timestamp = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;

    csvFile << packetCount << "," << timestamp << "," << src_ip << "," << dst_ip << ","
            << src_port << "," << dst_port << ",\"" << ftp_command << "\"" << endl;
}

int main() {
    const char* filename = "ftp.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        cerr << "Error opening file: " << errbuf << endl;
        return 1;
    }

    csvFile.open("ftp_packets.csv");
    if (!csvFile) {
        cerr << "Error creating output CSV file." << endl;
        return 1;
    }

    csvFile << "frame.number,frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,ftp.request.command" << endl;

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    csvFile.close();

    cout << "Done. Output saved to ftp_packets.csv" << endl;
    cout << "Total packets processed: " << packetCount << endl;
    return 0;
}
