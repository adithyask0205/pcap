#include <pcap.h>        // For reading pcap files
#include <iostream>      // For printing messages
#include <netinet/ip.h>  // For IP header stuff
#include <netinet/tcp.h> // For TCP header stuff
#include <arpa/inet.h>   // For IP address conversion
#include <cstring>       // For char array operations
#include<vector>        // For using vector container

using namespace std;

// Class to handle reading and processing packets from a pcap file
class PacketReader {
private:
    const char* pcap_filename; // Name of the pcap file to read
    char error_buffer[PCAP_ERRBUF_SIZE]; // Buffer to store error messages
    vector<pcap_pkthdr> packet_headers; // Vector to store packet headers (if needed)

    // Helper function to print IP address as a string
    void print_ip_address(const char* label, in_addr address) {
        char ip_str[INET_ADDRSTRLEN];
        // Convert IP address to string
        strncpy(ip_str, inet_ntoa(address), INET_ADDRSTRLEN - 1);
        ip_str[INET_ADDRSTRLEN - 1] = '\0';
        cout << label << ip_str << "\n";
    }

    // Static callback for pcap_loop; forwards to instance method
    static void packet_handler_callback(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet_data) {
        PacketReader* reader = reinterpret_cast<PacketReader*>(user_data);
        reader->process_packet(header, packet_data);
    }

    // Process a single packet
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet_data) {
        // Ethernet header is 14 bytes; skip it to get to IP header
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet_data + 14);
        int ip_header_length = ip_header->ip_hl * 4; // IP header length in bytes

        // Only process TCP packets
        if (ip_header->ip_p != IPPROTO_TCP) return;

        // Get TCP header
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet_data + 14 + ip_header_length);

        // Print source and destination IP addresses
        print_ip_address("Source IP: ", ip_header->ip_src);
        print_ip_address("Destination IP: ", ip_header->ip_dst);

        // Print source and destination ports
        cout << "Source Port: " << ntohs(tcp_header->th_sport) << "\n";
        cout << "Destination Port: " << ntohs(tcp_header->th_dport) << "\n";
        cout << "--------------------------------------------\n";
    }

public:
    // Constructor to initialize with filename
    PacketReader(const char* filename) : pcap_filename(filename) {
        // Initialize error buffer to empty string
        error_buffer[0] = '\0';
    }

    // Main function to read and process packets
    void read_packets() {
        // Open the pcap file for offline processing
        pcap_t* pcap_handle = pcap_open_offline(pcap_filename, error_buffer);
        if (pcap_handle == nullptr) {
            cerr << "Couldn't open file: " << error_buffer << endl;
            return;
        }

        // Use pcap_loop to process all packets, passing 'this' as user data
        pcap_loop(pcap_handle, 0, PacketReader::packet_handler_callback, reinterpret_cast<u_char*>(this));

        // Close the pcap file
        pcap_close(pcap_handle);
    }
};

// Entry point of the program
int main() {
    // Create a PacketReader object for the given pcap file
    PacketReader reader("./ftp.pcap");
    // Read and process packets
    reader.read_packets();
    return 0;
}
