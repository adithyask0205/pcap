#include <pcap.h>
#include <iostream>
#include <fstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <thread>
#include <queue>
#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <sstream>

using namespace std;

struct Packet {
    vector<unsigned char> data;
    double timestamp;
    int number;
};

queue<Packet> packet_queue;
mutex queue_mutex;
ofstream csv_file;
mutex csv_mutex;
atomic<bool> reading_done(false);
atomic<int> packet_counter(0);

atomic<int> produced_this_sec(0);
atomic<int> consumed_this_sec(0);
atomic<int> producer_threads(0);
atomic<int> consumer_threads(0);
const int MAX_PRODUCERS = 3;
const int MAX_CONSUMERS = 5;

void producer(string filename) {
    producer_threads++;
    cout << "Reading packets from " << filename << endl;
    char error[256];

    pcap_t* handle = pcap_open_offline(filename.c_str(), error);
    if (!handle) {
        cout << "Error opening file: " << error << endl;
        producer_threads--;
        return;
    }

    struct pcap_pkthdr header;
    const unsigned char* data;

    while ((data = pcap_next(handle, &header)) != nullptr) {
        Packet pkt;
        pkt.number = ++packet_counter;
        produced_this_sec++;
        pkt.timestamp = header.ts.tv_sec + header.ts.tv_usec / 1000000.0;
        pkt.data.assign(data, data + header.caplen);
        {
            lock_guard<mutex> lock(queue_mutex);
            packet_queue.push(pkt);
        }
        cout << "Read packet " << pkt.number << endl;
    }
    pcap_close(handle);

    reading_done = true;
    producer_threads--;

    cout << "Finished reading packets" << endl;
}

void consumer() {
    consumer_threads++;
    cout << "Processing packets..." << endl;

    while (true) {
        Packet pkt;
        bool got_packet = false;
        {
            lock_guard<mutex> lock(queue_mutex);
            if (!packet_queue.empty()) {
                pkt = packet_queue.front();
                packet_queue.pop();
                got_packet = true;
            }
        }

        if (!got_packet) {
            if (reading_done) break;
            this_thread::sleep_for(chrono::milliseconds(10));
            continue;
        }

        consumed_this_sec++;
        string src_ip = "unknown", dst_ip = "unknown";
        int src_port = 0, dst_port = 0;
        string protocol = "unknown";
        if (pkt.data.size() >= 34) {
            struct ip* ip_hdr = (struct ip*)&pkt.data[14];
            src_ip = inet_ntoa(ip_hdr->ip_src);
            dst_ip = inet_ntoa(ip_hdr->ip_dst);
            if (ip_hdr->ip_p == IPPROTO_TCP) {
                protocol = "TCP";
                int ip_len = ip_hdr->ip_hl * 4;
                if (pkt.data.size() >= 14 + ip_len + 20) {
                    struct tcphdr* tcp_hdr = (struct tcphdr*)&pkt.data[14 + ip_len];
                    src_port = ntohs(tcp_hdr->th_sport);
                    dst_port = ntohs(tcp_hdr->th_dport);
                    if (src_port == 21 || dst_port == 21) {
                        protocol = "FTP";
                    }
                }
            }
        }

        {
            time_t t = (time_t)pkt.timestamp;
            tm tm = *localtime(&t);
            int millis = (int)((pkt.timestamp - t) * 1000);
            ostringstream oss;
            oss << put_time(&tm, "%Y-%m-%d %H:%M:%S");
            oss << '.' << setfill('0') << setw(3) << millis;
            lock_guard<mutex> lock(csv_mutex);
            csv_file << pkt.number << "," << oss.str() << ","
                     << src_ip << "," << dst_ip << ","
                     << src_port << "," << dst_port << ","
                     << protocol << endl;
        }

        cout << "Processed packet " << pkt.number << " (" << protocol << ")" << endl;
    }

    consumer_threads--;
    cout << "Finished processing packets" << endl;
}

void manager(vector<thread>& producers, vector<thread>& consumers, string filename) {
    while (true) {
        this_thread::sleep_for(chrono::seconds(1));
        int prod = producer_threads.load();
        int cons = consumer_threads.load();
        int produced = produced_this_sec.exchange(0);
        int consumed = consumed_this_sec.exchange(0);
        int qsize;

        {
            lock_guard<mutex> lock(queue_mutex);
            qsize = packet_queue.size();
        }

        cout << "[Manager] Producers: " << prod << ", Consumers: " << cons
             << ", Produced: " << produced << ", Consumed: " << consumed
             << ", Queue: " << qsize << endl;

        if (produced > consumed * 1.5 && cons < MAX_CONSUMERS) {
            cout << "[Manager] Spawning extra consumer..." << endl;
            consumers.emplace_back(consumer);
        }

        if (consumed > produced * 1.5 && prod < MAX_PRODUCERS && !reading_done) {
            cout << "[Manager] Spawning extra producer..." << endl;
            producers.emplace_back(producer, filename);
        }

        if (reading_done && qsize == 0 && prod == 0) break;
    }
}

int main() {
    cout << "=== Simple PCAP Processor ===" << endl;
    csv_file.open("packets.csv");

    if (!csv_file.is_open()) {
        cout << "Error: Cannot create CSV file" << endl;
        return 1;
    }

    csv_file << "packet_number,timestamp,source_ip,dest_ip,source_port,dest_port,protocol" << endl;
    
    vector<thread> producers, consumers;
    string filename = "ftp.pcap";

    producers.emplace_back(producer, filename);
    consumers.emplace_back(consumer);

    thread mgr(manager, ref(producers), ref(consumers), filename);

    for (auto& t : producers) t.join();
    for (auto& t : consumers) t.join();
    mgr.join();
    csv_file.close();
    
    cout << "\n=== DONE ===" << endl;
    cout << "Results saved to: packets.csv" << endl;
    cout << "Total packets processed: " << packet_counter << endl;
    return 0;
}