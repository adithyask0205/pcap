#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct ip* ip_hdr = (struct ip*)(packet + 14);
    int ip_header_len = ip_hdr->ip_hl * 4;

    if (ip_hdr->ip_p != IPPROTO_TCP) return;  // Not a TCP packet

    const struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + ip_header_len);

    cout << "Source IP: " << inet_ntoa(ip_hdr->ip_src) << "\n";
    cout << "Destination IP: " << inet_ntoa(ip_hdr->ip_dst) << "\n";
    cout << "Source Port: " << ntohs(tcp_hdr->th_sport) << "\n";
    cout << "Destination Port: " << ntohs(tcp_hdr->th_dport) << "\n";
    cout << "--------------------------------------------\n";
}

int main() {
    const char* filename = "./ftp.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (handle == nullptr) {
        cerr << "Couldn't open file: " << errbuf << endl;
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}
