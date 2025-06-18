#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// 16비트 타입 정의
using u16 = uint16_t;

//
// 헬퍼 함수 및 구조체 선언
//

// 프로그램 사용법 안내 함수
void usage() {
    std::cout << "syntax : tls-block <interface> <host>\n";
    std::cout << "sample : tls-block wlan0 test.gilgil.net\n";
}

// IP/TCP 체크섬 계산 함수
u16 compute_checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<u16>(~sum);
}

// 네트워크 인터페이스의 MAC 주소를 가져오는 함수
bool get_my_mac(const std::string& dev, uint8_t* mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }

    ifreq ifr{};
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return false;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return true;
}

// TLS Client Hello 메시지에서 SNI(서버 이름)를 파싱하는 함수
std::string parse_sni(const uint8_t* data, size_t len) {
    // 1. 레코드 레이어 확인 (타입: Handshake, 0x16)
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t record_len = (data[3] << 8) | data[4];
    if (len < 5 + record_len) return "";
    size_t pos = 5; // 레코드 헤더 크기

    // 2. 핸드셰이크 프로토콜 확인 (타입: Client Hello, 0x01)
    if (pos + 4 > len || data[pos] != 0x01) return "";
    pos += 4; // 핸드셰이크 헤더 크기

    // 3. 주요 필드 건너뛰기
    pos += 2 + 32; // Version + Random
    if (pos >= len) return "";

    uint8_t session_id_len = data[pos++];
    pos += session_id_len; // Session ID
    if (pos + 2 > len) return "";

    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos+1];
    pos += 2 + cipher_suites_len; // Cipher Suites
    if (pos >= len) return "";
    
    uint8_t comp_methods_len = data[pos++];
    pos += comp_methods_len; // Compression Methods
    if (pos + 2 > len) return "";

    // 4. 확장(Extensions) 영역에서 SNI 찾기
    uint16_t extensions_total_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    size_t end_of_extensions = pos + extensions_total_len;

    while (pos + 4 <= end_of_extensions && pos + 4 <= len) {
        uint16_t ext_type = (data[pos] << 8) | data[pos+1];
        uint16_t ext_len  = (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        // SNI 확장 타입은 0x0000
        if (ext_type == 0x0000) {
            if (pos + ext_len > end_of_extensions) return "";
            pos += 3; // Server Name list length (2 bytes) + Server Name Type (1 byte)
            uint16_t server_name_len = (data[pos] << 8) | data[pos+1];
            pos += 2;
            if (pos + server_name_len <= end_of_extensions) {
                return std::string(reinterpret_cast<const char*>(data + pos), server_name_len);
            }
            return "";
        }
        pos += ext_len;
    }
    return "";
}

// TCP Flow를 식별하기 위한 키 구조체
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port;
    }
};

// FlowKey를 unordered_map에서 사용하기 위한 해시 함수
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        return std::hash<uint32_t>()(k.src_ip) ^
               (std::hash<uint32_t>()(k.dst_ip) << 1) ^
               (std::hash<uint16_t>()(k.src_port) << 16) ^
               (std::hash<uint16_t>()(k.dst_port) << 17);
    }
};

// TCP 재조합을 위한 버퍼 구조체
struct ReassemblyBuffer {
    std::vector<uint8_t> buffer;
    uint32_t base_seq = 0;
    size_t expected_len = 0;
    bool in_progress = false;
};

//
// 패킷 주입 함수
//

// Forward RST (Client -> Server) 패킷 주입
void inject_forward_rst(pcap_t* handle, const uint8_t* original_packet, const ip* iph, const tcphdr* tcph, int data_len, const uint8_t* my_mac) {
    uint8_t new_packet[1500];
    int ip_header_len = iph->ip_hl * 4;
    int tcp_header_len = tcph->th_off * 4;
    int header_size = sizeof(ether_header) + ip_header_len + tcp_header_len;

    // 1. 원본 패킷의 헤더 복사
    memcpy(new_packet, original_packet, header_size);
    
    // 2. 이더넷 헤더 수정 (Source MAC을 내 MAC으로)
    auto* eth_hdr = reinterpret_cast<ether_header*>(new_packet);
    memcpy(eth_hdr->ether_shost, my_mac, ETHER_ADDR_LEN);

    // 3. IP 헤더 수정
    auto* ip_hdr = reinterpret_cast<ip*>(new_packet + sizeof(ether_header));
    ip_hdr->ip_len = htons(ip_header_len + tcp_header_len);
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = compute_checksum(reinterpret_cast<u16*>(ip_hdr), ip_header_len);

    // 4. TCP 헤더 수정
    auto* tcp_hdr = reinterpret_cast<tcphdr*>(new_packet + sizeof(ether_header) + ip_header_len);
    tcp_hdr->th_seq = htonl(ntohl(tcph->th_seq) + data_len);
    tcp_hdr->th_flags = TH_RST | TH_ACK;
    tcp_hdr->th_win = 0;
    tcp_hdr->th_sum = 0;
    
    // 5. TCP 체크섬 재계산 (의사 헤더 사용)
    struct PseudoHeader {
        uint32_t src_ip, dst_ip;
        uint8_t reserved, protocol;
        uint16_t tcp_len;
    } pseudo_hdr;

    pseudo_hdr.src_ip = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dst_ip = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_len = htons(tcp_header_len);

    std::vector<uint8_t> checksum_buf(sizeof(PseudoHeader) + tcp_header_len);
    memcpy(checksum_buf.data(), &pseudo_hdr, sizeof(PseudoHeader));
    memcpy(checksum_buf.data() + sizeof(PseudoHeader), tcp_hdr, tcp_header_len);
    tcp_hdr->th_sum = compute_checksum(reinterpret_cast<u16*>(checksum_buf.data()), checksum_buf.size());

    // 6. 패킷 주입
    if (pcap_sendpacket(handle, new_packet, header_size) != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", -1, pcap_geterr(handle));
    }
}

// Backward RST (Server -> Client) 패킷 주입
void inject_backward_rst(const ip* iph, const tcphdr* tcph, int data_len) {
    int ip_header_len = iph->ip_hl * 4;
    int tcp_header_len = tcph->th_off * 4;
    int packet_size = ip_header_len + tcp_header_len;
    std::vector<uint8_t> new_packet(packet_size);

    // 1. IP 헤더 생성 및 수정 (Source/Dest IP 주소 교환)
    auto* ip_hdr = reinterpret_cast<ip*>(new_packet.data());
    memcpy(ip_hdr, iph, ip_header_len);
    ip_hdr->ip_src = iph->ip_dst;
    ip_hdr->ip_dst = iph->ip_src;
    ip_hdr->ip_len = htons(packet_size);
    ip_hdr->ip_ttl = 128;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = compute_checksum(reinterpret_cast<u16*>(ip_hdr), ip_header_len);

    // 2. TCP 헤더 생성 및 수정 (Source/Dest Port 교환)
    auto* tcp_hdr = reinterpret_cast<tcphdr*>(new_packet.data() + ip_header_len);
    memcpy(tcp_hdr, tcph, tcp_header_len);
    tcp_hdr->th_sport = tcph->th_dport;
    tcp_hdr->th_dport = tcph->th_sport;
    tcp_hdr->th_seq = tcph->th_ack; // 받은 ack을 나의 seq로
    tcp_hdr->th_ack = htonl(ntohl(tcph->th_seq) + data_len);
    tcp_hdr->th_flags = TH_RST | TH_ACK;
    tcp_hdr->th_win = 0;
    tcp_hdr->th_sum = 0;

    // 3. TCP 체크섬 재계산
    struct PseudoHeader {
        uint32_t src_ip, dst_ip;
        uint8_t reserved, protocol;
        uint16_t tcp_len;
    } pseudo_hdr;
    pseudo_hdr.src_ip = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dst_ip = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_len = htons(tcp_header_len);
    
    std::vector<uint8_t> checksum_buf(sizeof(PseudoHeader) + tcp_header_len);
    memcpy(checksum_buf.data(), &pseudo_hdr, sizeof(PseudoHeader));
    memcpy(checksum_buf.data() + sizeof(PseudoHeader), tcp_hdr, tcp_header_len);
    tcp_hdr->th_sum = compute_checksum(reinterpret_cast<u16*>(checksum_buf.data()), checksum_buf.size());

    // 4. Raw Socket을 이용해 패킷 주입
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket");
        return;
    }
    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sd);
        return;
    }
    sockaddr_in dst_addr{};
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr = ip_hdr->ip_dst;
    sendto(sd, new_packet.data(), packet_size, 0, reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr));
    close(sd);
}


//
// 메인 로직
//

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }
    std::string dev = argv[1];
    std::string host_pattern = argv[2];

    // 1. 내 MAC 주소 가져오기
    uint8_t my_mac[ETHER_ADDR_LEN];
    if (!get_my_mac(dev, my_mac)) {
        std::cerr << "Failed to get MAC address for " << dev << std::endl;
        return -1;
    }

    // 2. pcap 핸들 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live(" << dev << ") return null - " << errbuf << std::endl;
        return -1;
    }

    // 3. 패킷 필터 설정
    bpf_program fp;
    std::string filter_exp = "tcp dst port 443";
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile(" << filter_exp << ") return -1" << std::endl;
        pcap_close(handle);
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter return -1" << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return -1;
    }
    pcap_freecode(&fp);
    
    // TCP 재조합을 위한 Flow 맵
    std::unordered_map<FlowKey, ReassemblyBuffer, FlowKeyHash> flows;

    std::cout << "Starting SNI blocker for host: " << host_pattern << std::endl;

    // 4. 패킷 캡처 루프 시작
    while (true) {
        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // Timeout
        if (res == -1 || res == -2) {
            std::cerr << "pcap_next_ex return " << res << "(" << pcap_geterr(handle) << ")" << std::endl;
            break;
        }

        // 5. 패킷 분석
        auto* eth_hdr = reinterpret_cast<const ether_header*>(packet);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

        auto* ip_hdr = reinterpret_cast<const ip*>(packet + sizeof(ether_header));
        if (ip_hdr->ip_p != IPPROTO_TCP) continue;

        int ip_header_len = ip_hdr->ip_hl * 4;
        auto* tcp_hdr = reinterpret_cast<const tcphdr*>(packet + sizeof(ether_header) + ip_header_len);
        int tcp_header_len = tcp_hdr->th_off * 4;
        
        int data_len = ntohs(ip_hdr->ip_len) - ip_header_len - tcp_header_len;
        if (data_len <= 0) continue;

        const uint8_t* payload = reinterpret_cast<const uint8_t*>(tcp_hdr) + tcp_header_len;

        // 6. SNI 파싱 및 차단 로직
        FlowKey key{ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr, tcp_hdr->th_sport, tcp_hdr->th_dport};
        auto& flow = flows[key];

        if (!flow.in_progress) {
             // 단일 패킷에서 SNI 확인
            std::string sni = parse_sni(payload, data_len);
            if (!sni.empty() && sni.find(host_pattern) != std::string::npos) {
                std::cout << "[Blocked] Found SNI: " << sni << std::endl;
                inject_forward_rst(handle, packet, ip_hdr, tcp_hdr, data_len, my_mac);
                inject_backward_rst(ip_hdr, tcp_hdr, data_len);
                flows.erase(key); // 처리 완료된 Flow는 맵에서 제거
                continue;
            }

            // 재조합 시작 조건 확인 (TLS Handshake Record)
            if (data_len >= 5 && payload[0] == 0x16) {
                uint16_t record_len = (payload[3] << 8) | payload[4];
                flow.expected_len = 5 + record_len;
                if (data_len < flow.expected_len) {
                    flow.in_progress = true;
                    flow.base_seq = ntohl(tcp_hdr->th_seq);
                    flow.buffer.assign(payload, payload + data_len);
                }
            }
        } else {
             // 재조합 진행
            uint32_t current_seq = ntohl(tcp_hdr->th_seq);
            size_t offset = current_seq - flow.base_seq;
            
            if (flow.buffer.size() < offset + data_len) {
                flow.buffer.resize(offset + data_len);
            }
            memcpy(flow.buffer.data() + offset, payload, data_len);

            // 재조합 완료 확인
            if (flow.buffer.size() >= flow.expected_len) {
                std::string sni = parse_sni(flow.buffer.data(), flow.buffer.size());
                if (!sni.empty() && sni.find(host_pattern) != std::string::npos) {
                    std::cout << "[Blocked after reassembly] Found SNI: " << sni << std::endl;
                    inject_forward_rst(handle, packet, ip_hdr, tcp_hdr, flow.buffer.size(), my_mac);
                    inject_backward_rst(ip_hdr, tcp_hdr, flow.buffer.size());
                }
                flows.erase(key); // 처리 완료
            }
        }
    }

    pcap_close(handle);
    return 0;
}
