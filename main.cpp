#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

// 전역으로 사용할 정적 전송 버퍼 (속도 최적화)
static uint8_t send_buffer[1500];

// 사용법 출력
void usage() {
    printf("syntax : tls-block <interface> <server_name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

// MAC 주소 획득
bool getMyMacAddress(const std::string& iface, uint8_t* mac_addr) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(mac)");
        close(sock);
        return false;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

// 체크섬 계산 함수
uint16_t calculateChecksum(uint16_t *buf, int nbytes) {
    unsigned long sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }
    if (nbytes) {
        sum += *(uint8_t*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

// SNI 파싱 함수
std::string parseSNI(const uint8_t* payload, int len) {
    if (len < 9 || payload[5] != 0x01) return ""; 
    
    int offset = 5 + 4; 
    offset += 2 + 32;
    
    if (offset >= len) return "";
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    if (offset + 2 > len) return "";
    uint16_t cipher_suites_len = ntohs(*(uint16_t*)(payload + offset));
    offset += 2 + cipher_suites_len;

    if (offset + 1 > len) return "";
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;

    if (offset + 2 > len) return "";
    uint16_t ext_total_len = ntohs(*(uint16_t*)(payload + offset));
    offset += 2;

    const uint8_t* p = payload + offset;
    const uint8_t* end = p + ext_total_len;
    if (end > payload + len) end = payload + len;

    while (p + 4 <= end) {
        uint16_t ext_type = ntohs(*(uint16_t*)p);
        uint16_t ext_len = ntohs(*(uint16_t*)(p + 2));
        p += 4;
        if (p + ext_len > end) break;
        
        if (ext_type == 0x0000) { 
            if (ext_len < 5) break;
            uint16_t name_len = ntohs(*(uint16_t*)(p + 3));
            if (p + 5 + name_len > end) break;
            return std::string((char*)(p + 5), name_len);
        }
        p += ext_len;
    }
    return "";
}

// 서버로 RST 전송
void sendForwardRst(pcap_t* pcap, const uint8_t* orig_packet, const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len, const uint8_t* my_mac) {
    int eth_sz = sizeof(struct ether_header);
    int ip_sz = ip_hdr->ip_hl * 4;
    int tcp_sz = tcp_hdr->th_off * 4;
    int total_hdr_sz = eth_sz + ip_sz + tcp_sz;
    
    memcpy(send_buffer, orig_packet, total_hdr_sz);

    struct ether_header* eth = reinterpret_cast<struct ether_header*>(send_buffer);
    memcpy(eth->ether_shost, my_mac, 6);

    struct ip* new_ip = reinterpret_cast<struct ip*>(send_buffer + eth_sz);
    new_ip->ip_len = htons(ip_sz + tcp_sz);
    new_ip->ip_sum = 0;
    new_ip->ip_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(new_ip), ip_sz));

    struct tcphdr* new_tcp = reinterpret_cast<struct tcphdr*>(send_buffer + eth_sz + ip_sz);
    new_tcp->th_seq = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    new_tcp->th_flags = TH_RST | TH_ACK;
    new_tcp->th_sum = 0;

    int pseudo_hdr_sz = 12 + tcp_sz;
    std::vector<uint8_t> pseudo_packet(pseudo_hdr_sz);
    memcpy(pseudo_packet.data(), &new_ip->ip_src, 8);
    pseudo_packet[8] = 0;
    pseudo_packet[9] = IPPROTO_TCP;
    uint16_t tcp_len_n = htons(tcp_sz);
    memcpy(pseudo_packet.data() + 10, &tcp_len_n, 2);
    memcpy(pseudo_packet.data() + 12, new_tcp, tcp_sz);
    new_tcp->th_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(pseudo_packet.data()), pseudo_hdr_sz));
    
    if (pcap_sendpacket(pcap, send_buffer, total_hdr_sz) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
    }
}

// 클라이언트로 RST 전송
void sendBackwardRst(const struct ip* ip_hdr, const struct tcphdr* tcp_hdr, int payload_len) {
    int ip_sz = sizeof(struct ip);
    int tcp_sz = sizeof(struct tcphdr);
    int total_sz = ip_sz + tcp_sz;

    memset(send_buffer, 0, total_sz);
    
    struct ip* new_ip = reinterpret_cast<struct ip*>(send_buffer);
    new_ip->ip_v = 4;
    new_ip->ip_hl = ip_sz / 4;
    new_ip->ip_len = htons(total_sz);
    new_ip->ip_ttl = 128;
    new_ip->ip_p = IPPROTO_TCP;
    new_ip->ip_src = ip_hdr->ip_dst;
    new_ip->ip_dst = ip_hdr->ip_src;
    new_ip->ip_sum = 0;
    new_ip->ip_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(new_ip), ip_sz));

    struct tcphdr* new_tcp = reinterpret_cast<struct tcphdr*>(send_buffer + ip_sz);
    new_tcp->th_sport = tcp_hdr->th_dport;
    new_tcp->th_dport = tcp_hdr->th_sport;
    new_tcp->th_seq = tcp_hdr->th_ack;
    new_tcp->th_ack = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    new_tcp->th_off = tcp_sz / 4;
    new_tcp->th_flags = TH_RST | TH_ACK;
    new_tcp->th_win = htons(60000);
    new_tcp->th_sum = 0;

    int pseudo_hdr_sz = 12 + tcp_sz;
    std::vector<uint8_t> pseudo_packet(pseudo_hdr_sz);
    memcpy(pseudo_packet.data(), &new_ip->ip_src, 8);
    pseudo_packet[8] = 0;
    pseudo_packet[9] = IPPROTO_TCP;
    uint16_t tcp_len_n = htons(tcp_sz);
    memcpy(pseudo_packet.data() + 10, &tcp_len_n, 2);
    memcpy(pseudo_packet.data() + 12, new_tcp, tcp_sz);
    new_tcp->th_sum = htons(calculateChecksum(reinterpret_cast<uint16_t*>(pseudo_packet.data()), pseudo_hdr_sz));

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket");
        return;
    }
    int on = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = new_tcp->th_dport;
    addr.sin_addr = new_ip->ip_dst;

    if (sendto(sd, send_buffer, total_sz, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
    }
    close(sd);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    std::string interface_name = argv[1];
    std::string server_name = argv[2];
    uint8_t my_mac[6];

    if (!getMyMacAddress(interface_name, my_mac)) {
        return -1;
    }
    
    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    printf("Interface: %s | MAC: %s\n", interface_name.c_str(), mac_str);
    printf("Blocking server pattern: %s\n", server_name.c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 올바른 pcap 초기화 순서
    pcap_t* pcap = pcap_create(interface_name.c_str(), errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_create() error: %s\n", errbuf);
        return -1;
    }
    pcap_set_snaplen(pcap, BUFSIZ);
    pcap_set_promisc(pcap, 1);
    pcap_set_timeout(pcap, 1);
    pcap_set_immediate_mode(pcap, 1);
    if (pcap_activate(pcap) != 0) {
        fprintf(stderr, "pcap_activate() error: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }
        
        const struct ether_header* eth_hdr = reinterpret_cast<const struct ether_header*>(packet);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;

        int ip_hdr_len = ip_hdr->ip_hl * 4;
        const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ether_header) + ip_hdr_len);
        int tcp_hdr_len = tcp_hdr->th_off * 4;
        
        int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len <= 5 || packet[sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len] != 0x16) continue;

        const uint8_t* payload = packet + sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;
        std::string hostname = parseSNI(payload, payload_len);

        if (!hostname.empty() && hostname.find(server_name) != std::string::npos) {
            printf("Target found in SNI: %s -> Blocking!\n", hostname.c_str());
            sendForwardRst(pcap, packet, ip_hdr, tcp_hdr, payload_len, my_mac);
            sendBackwardRst(ip_hdr, tcp_hdr, payload_len);
        }
    }

    pcap_close(pcap);
    return 0;
}
