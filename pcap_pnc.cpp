#include <pcap.h>        // For reading pcap files
#include <iostream>      // For printing messages
#include <fstream>       // For file output
#include <netinet/ip.h>  // For IP header stuff
#include <netinet/tcp.h> // For TCP header stuff
#include <arpa/inet.h>   // For IP address conversion
#include <cstring>       // For char array operations
#include <queue>         // For my packet queue
#include <mutex>         // For locking shared data
#include <thread>        // For running threads
#include <atomic>        // For atomic flags and counters
#include <chrono>        // For sleep

using namespace std;

const int MAX_FILENAME_LEN = 256;
const int IP_LEN = 16;
const int PROTO_LEN = 8;
const int CSV_LINE_MAX = 128;
const int PACKET_BUF_MAX = 65536;

// Packet class to hold info
class Packet {
public:
    unsigned char buf[PACKET_BUF_MAX]; // Actual packet data
    int len;                           // How much data
    double ts;                         // Timestamp
    int idx;                           // Packet number
    Packet() : len(0), ts(0.0), idx(0) { memset(buf, 0, sizeof(buf)); }
};

// Thread-safe queue for packets
class PacketQueue {
    queue<Packet> queue;
    mutex mutex;
public:
    // Add a packet to the queue (thread-safe)
    void push(const Packet& pkt) {
        lock_guard<mutex> lock(mutex);
        queue.push(pkt);
    }
    // Try to pop a packet from the queue (thread-safe)
    bool pop(Packet& pkt) {
        lock_guard<mutex> lock(mutex);
        if (queue.empty()) return false;
        pkt = queue.front();
        queue.pop();
        return true;
    }
    // Get current queue size (thread-safe)
    int size() {
        lock_guard<mutex> lock(mutex);
        return static_cast<int>(queue.size());
    }
};

// CSV writer with locking
class CsvWriter {
    ofstream file;
    mutex mutex;
public:
    CsvWriter(const char* filename) { file.open(filename); }
    ~CsvWriter() { if (file.is_open()) file.close(); }
    // Write CSV header
    void writeHeader() {
        writeLine("packet_number,timestamp,source_ip,dest_ip,source_port,dest_port,protocol");
    }
    void writeLine(const char* line) {
        lock_guard<mutex> lock(mutex);
        file << line << endl;
    }
    bool isOpen() const { return file.is_open(); }
};

// Producer class: reads packets from pcap file and enqueues them
class Producer {
    PacketQueue& packetQueue;
    atomic<int>& totalPacketCount;
    atomic<bool>& readingDone;
    char filename[MAX_FILENAME_LEN];
public:
    Producer(PacketQueue& pq, atomic<int>& count, atomic<bool>& done, const char* fname)
        : packetQueue(pq), totalPacketCount(count), readingDone(done) {
        strncpy(filename, fname, MAX_FILENAME_LEN);
        filename[MAX_FILENAME_LEN-1] = '\0';
    }
    void operator()() {
        char errbuf[PCAP_ERRBUF_SIZE];
        // Open the pcap file for reading
        pcap_t* handle = pcap_open_offline(filename, errbuf);
        if (!handle) { cout << "Error opening file: " << errbuf << endl; readingDone = true; return; }
        struct pcap_pkthdr* header; const u_char* data; int res;
        // Read packets one by one
        while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
            Packet pkt;
            pkt.idx = ++totalPacketCount;
            pkt.ts = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
            pkt.len = (header->caplen < PACKET_BUF_MAX) ? header->caplen : PACKET_BUF_MAX;
            memcpy(pkt.buf, data, pkt.len);
            packetQueue.push(pkt); // Enqueue the packet for consumers
        }
        pcap_close(handle);
        readingDone = true; // Signal consumers that reading is done
    }
};

// Consumer class: dequeues packets, parses, and writes to CSV
class Consumer {
    PacketQueue& packetQueue;
    CsvWriter& csvWriter;
    atomic<bool>& readingDone;
public:
    Consumer(PacketQueue& pq, CsvWriter& cw, atomic<bool>& done)
        : packetQueue(pq), csvWriter(cw), readingDone(done) {}
    void operator()() {
        while (true) {
            Packet pkt;
            // Try to get a packet from the queue
            if (!packetQueue.pop(pkt)) {
                if (readingDone) break; // Exit if producer is done and queue is empty
                this_thread::sleep_for(chrono::milliseconds(10));
                continue;
            }
            // Default values
            char src[IP_LEN] = "unknown", dst[IP_LEN] = "unknown";
            int sport = 0, dport = 0;
            char proto[PROTO_LEN] = "unknown";
            // Parse IP and TCP headers if possible
            if (pkt.len >= 34) {
                struct ip* iph = (struct ip*)(pkt.buf + 14); // Ethernet header is 14 bytes
                strncpy(src, inet_ntoa(iph->ip_src), IP_LEN-1);
                strncpy(dst, inet_ntoa(iph->ip_dst), IP_LEN-1);
                src[IP_LEN-1] = '\0'; dst[IP_LEN-1] = '\0';
                if (iph->ip_p == IPPROTO_TCP) {
                    strcpy(proto, "TCP");
                    int iplen = iph->ip_hl * 4;
                    if (pkt.len >= 14 + iplen + 20) {
                        struct tcphdr* tcph = (struct tcphdr*)(pkt.buf + 14 + iplen);
                        sport = ntohs(tcph->th_sport);
                        dport = ntohs(tcph->th_dport);
                        if (sport == 21 || dport == 21) strcpy(proto, "FTP");
                    }
                }
            }
            // Format timestamp
            time_t t = (time_t)pkt.ts;
            tm tmStruct = *localtime(&t);
            int millis = (int)((pkt.ts - t) * 1000);
            char timeStr[32];
            snprintf(timeStr, sizeof(timeStr), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                tmStruct.tm_year + 1900, tmStruct.tm_mon + 1, tmStruct.tm_mday,
                tmStruct.tm_hour, tmStruct.tm_min, tmStruct.tm_sec, millis);
            // Write to CSV
            char line[CSV_LINE_MAX];
            snprintf(line, sizeof(line), "%d,%s,%s,%s,%d,%d,%s",
                pkt.idx, timeStr, src, dst, sport, dport, proto);
            csvWriter.writeLine(line); // Write to CSV
        }
    }
};

int main() {
    cout << "=== My PCAP to CSV Tool (C++ OOP, char arrays) ===" << endl;
    PacketQueue packetQueue;
    atomic<int> totalPacketCount(0);
    atomic<bool> readingDone(false);
    CsvWriter csvWriter("packets.csv");
    if (!csvWriter.isOpen()) {
        cout << "Couldn't create CSV file!" << endl;
        return 1;
    }
    csvWriter.writeHeader();
    const char* pcapFile = "ftp.pcap"; // You can change this if needed
    // Set up producer and consumers
    Producer producer(packetQueue, totalPacketCount, readingDone, pcapFile);
    Consumer consumer1(packetQueue, csvWriter, readingDone);
    Consumer consumer2(packetQueue, csvWriter, readingDone);
    // Start threads
    thread tProd(ref(producer));
    thread tCons1(ref(consumer1));
    thread tCons2(ref(consumer2));
    // Wait for all to finish
    tProd.join();
    tCons1.join();
    tCons2.join();
    cout << "\n=== DONE ===" << endl;
    cout << "Results saved to: packets.csv" << endl;
    cout << "Total packets processed: " << totalPacketCount << endl;
    return 0;
}