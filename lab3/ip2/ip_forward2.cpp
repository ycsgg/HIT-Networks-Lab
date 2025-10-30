#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <map>
#include <vector>

#define BUFFER_SIZE  1518

// --- 结构体和数据类型定义 ---

// 路由表项： 目标IP 和 下一跳MAC地址
struct ForwardEntry {
    in_addr_t dest_ip;
    unsigned char next_hop_mac[ETH_ALEN];
};

// 路由配置： 当前主机的身份信息和要忽略的IP
struct RouterConfig {
    const char* router_name;
    const char* router_ip_str;
    const unsigned char router_mac[ETH_ALEN];
    const char* ignore_ip_str;
    const std::vector<ForwardEntry> routing_table;
};

// --- 全局 MAC 定义 ---
/**
192.168.1.2 00:0c:29:52:c2:ba
192.168.1.3 00:0c:29:c9:89:13
192.168.1.4 00:0c:29:05:82:fe
192.168.1.5 00:0c:29:ee:bb:99
192.168.1.6 00:0c:29:1c:6f:cf
**/
const unsigned char MAC_1_1[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x52, 0xc2, 0xba}; 
const unsigned char MAC_1_2[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xc9, 0x89, 0x13};
const unsigned char MAC_1_3[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x05, 0x82, 0xfe}; 
const unsigned char MAC_1_4[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xee, 0xbb, 0x99};
const unsigned char MAC_1_5[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x1c, 0x6f, 0xcf};
const in_addr_t DEFAULT_ROUTE_IP = inet_addr("0.0.0.0");

// --- 路由配置实例 ---

// Router 1 (192.168.1.2) 配置
const RouterConfig config1 = {
    "Router 1", "192.168.10.3",
    {0x00, 0x0c, 0x29, 0xc9, 0x89, 0x13},
    "192.168.10.1",
    {
        {inet_addr("0.0.0.0"), {0x00, 0x0c, 0x29, 0x05, 0x82, 0xfe}}
    }
};

const RouterConfig config2 = {
    "Router 2", "192.168.10.4",
    {0x00, 0x0c, 0x29, 0x05, 0x82, 0xfe},
    "192.168.10.1", 
    {
        {inet_addr("0.0.0.0"), {0x00, 0x0c, 0x29, 0xee, 0xbb, 0x99}}
    }
};

const RouterConfig config3 = {
    "Router 3", "192.168.10.5",
    {0x00, 0x0c, 0x29, 0xee, 0xbb, 0x99},
    "192.168.10.1", 
    {
        {inet_addr("192.168.10.6"), {0x00, 0x0c, 0x29, 0x1c, 0x6f, 0xcf}}
    }
};

// --- 通用函数 ---

// 获取当前时间字符串
std::string get_current_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// 计算 IP 头部校验和
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// MAC 地址转字符串
std::string mac_to_str(const unsigned char* mac) {
    char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// 打印数据包信息
void print_packet_info(const unsigned char* buffer, ssize_t len, const char* stage) {
    const struct ether_header *eh = (const struct ether_header *)buffer;
    const struct iphdr *iph = (const struct iphdr *)(buffer + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, dst_ip, INET_ADDRSTRLEN);

    std::cout << "\n[" << get_current_time() << " LOG: " << stage << "] 数据包 (" << len << " 字节):" << std::endl;
    std::cout << "  [L2] Src MAC: " << mac_to_str(eh->ether_shost) << std::endl;
    std::cout << "  [L2] Dst MAC: " << mac_to_str(eh->ether_dhost) << std::endl;
    std::cout << "  [L3] Src IP: " << src_ip << std::endl;
    std::cout << "  [L3] Dst IP: " << dst_ip << std::endl;
    std::cout << "  [L3] TTL: " << (int)iph->ttl << std::endl;
    std::cout << "  [L3] IP Checksum: 0x" << std::hex << ntohs(iph->check) << std::dec << std::endl;
    if (iph->protocol == IPPROTO_UDP) {
         const struct udphdr *udph = (const struct udphdr *)(buffer + sizeof(struct ether_header) + (iph->ihl * 4));
         std::cout << "  [L4] UDP Src Port: " << ntohs(udph->source) << std::endl;
         std::cout << "  [L4] UDP Dst Port: " << ntohs(udph->dest) << std::endl;
         // 假设是文本负载，为了简化，只打印可见字符
         const char* payload = (const char*)(buffer + sizeof(struct ether_header) + (iph->ihl * 4) + sizeof(struct udphdr));
         // 检查 UDP 负载长度，防止越界或打印垃圾
         int payload_len = ntohs(udph->len) - sizeof(struct udphdr);
         std::cout << "  [L4] Payload (max 32 bytes): ";
         for(int i = 0; i < std::min(payload_len, 32); ++i) {
             if (isprint(payload[i])) std::cout << payload[i];
             else std::cout << '.';
         }
         std::cout << std::endl;
    }
}

// 查找路由表
const unsigned char* find_next_hop(const RouterConfig& config, in_addr_t dest_ip) {
    const unsigned char* default_mac = nullptr;
    
    for (const auto& entry : config.routing_table) {
        if (entry.dest_ip == dest_ip) {
            // 找到精确匹配
            return entry.next_hop_mac;
        }
        if (entry.dest_ip == DEFAULT_ROUTE_IP) {
            // 记录默认路由
            default_mac = entry.next_hop_mac;
        }
    }
    
    // 如果没有找到精确匹配，返回默认路由
    return default_mac; 
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        std::cerr << "错误: 必须使用 root 权限运行此程序 (sudo)." << std::endl;
        return 1;
    }

    if (argc != 2) {
        std::cerr << "用法: " << argv[0] << "<1|2|3>" << std::endl;
        return 1;
    }

    const char* INTERFACE_NAME = "ens33";
    int config_idx = std::atoi(argv[1]);
    const RouterConfig* current_config = nullptr;

    // 1. 根据命令行参数选择配置
    switch (config_idx) {
        case 1: current_config = &config1; break;
        case 2: current_config = &config2; break;
        case 3: current_config = &config3; break;
        default:
            return 1;
    }

    struct in_addr ignore_ip_addr;
    if (inet_pton(AF_INET, current_config->ignore_ip_str, &ignore_ip_addr) != 1) {
        std::cerr << "[" << get_current_time() << " LOG] 无法解析配置的忽略 IP: " << current_config->ignore_ip_str << std::endl;
        return 1;
    }

    int sockfd;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    unsigned char buffer[BUFFER_SIZE];
    
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("socket failed (need root)");
        return 1;
    }
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind failed");
        close(sockfd);
        return 1;
    }
    
    std::cout << "--- 路由器配置信息 ---" << std::endl;
    std::cout << "[" << get_current_time() << " LOG: FORWARD] 启动 " << current_config->router_name << std::endl;
    std::cout << "接口: " << INTERFACE_NAME << ", IP: " << current_config->router_ip_str << ", MAC: " << mac_to_str(current_config->router_mac) << std::endl;
    std::cout << "忽略 IP: " << current_config->ignore_ip_str << std::endl;
    std::cout << "路由表: " << std::endl;
    for (const auto& entry : current_config->routing_table) {
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &entry.dest_ip, dest_ip, INET_ADDRSTRLEN);
        std::cout << "  Dst IP: " << dest_ip << " -> Next Hop MAC: " << mac_to_str(entry.next_hop_mac) << std::endl;
    }
    std::cout << "----------------------" << std::endl;
    std::cout << "等待数据包..." << std::endl;

    while (1) {
        ssize_t received_bytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);

        if (received_bytes < (ssize_t)(sizeof(struct ether_header) + sizeof(struct iphdr))) {
            if (received_bytes > 0) std::cerr << "收到过小的包，丢弃。" << std::endl;
            continue;
        }

        struct ether_header *eh = (struct ether_header *)buffer;
        struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct ether_header));
        
        if (memcmp(eh->ether_dhost, current_config->router_mac, ETH_ALEN) != 0) {
            continue;
        }

        if (ip_hdr->saddr == ignore_ip_addr.s_addr || ip_hdr->daddr == ignore_ip_addr.s_addr) {
             char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
             inet_ntop(AF_INET, &ip_hdr->saddr, src_ip_str, INET_ADDRSTRLEN);
             inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip_str, INET_ADDRSTRLEN);
            continue;
        }

        print_packet_info(buffer, received_bytes, "RECV");

        // 查表转发逻辑
        const unsigned char* next_hop_mac = find_next_hop(*current_config, ip_hdr->daddr);

        if (next_hop_mac == nullptr) {
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr->daddr, dest_ip, INET_ADDRSTRLEN);
            std::cerr << "[" << get_current_time() << " LOG: DROP] 目的 IP (" << dest_ip << ") 未找到路由，丢弃数据包。" << std::endl;
            continue;
        }

        if (ip_hdr->ttl <= 1) {
            std::cerr << "[" << get_current_time() << " LOG: DROP] TTL 过期 (" << (int)ip_hdr->ttl << ")，丢弃数据包。" << std::endl;
            continue;
        }

        ip_hdr->ttl--;
        ip_hdr->check = 0; 
        ip_hdr->check = checksum((unsigned short *)ip_hdr, sizeof(struct iphdr));

        // 修改 L2 头部
        memcpy(eh->ether_shost, current_config->router_mac, ETH_ALEN); // Src MAC: 路由器 MAC
        memcpy(eh->ether_dhost, next_hop_mac, ETH_ALEN);             // Dst MAC: 下一跳 MAC

        print_packet_info(buffer, received_bytes, "FORWARD");

        // 重新发送数据包
        memset(&socket_address, 0, sizeof(struct sockaddr_ll));
        socket_address.sll_ifindex = if_idx.ifr_ifindex;
        socket_address.sll_halen = ETH_ALEN;
        memcpy(socket_address.sll_addr, next_hop_mac, ETH_ALEN);

        if (sendto(sockfd, buffer, received_bytes, 0, (struct sockaddr *)&socket_address,
                   sizeof(struct sockaddr_ll)) < 0) {
            perror("sendto forward failed");
        } else {
            std::cout << "[" << get_current_time() << " LOG: FORWARD] 成功转发 " << received_bytes << " 字节到下一跳: " << mac_to_str(next_hop_mac) << std::endl;
        }
    }

    close(sockfd);
    return 0;
}