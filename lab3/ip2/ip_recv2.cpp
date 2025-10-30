#include <arpa/inet.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

const char *INTERFACE_NAME = "ens33";
const char *IGNORE_IP_STR = "192.168.10.1";
const unsigned char RECEIVER_MAC[6] = {0x00, 0x0c, 0x29, 0x1c, 0x6f, 0xcf};
#define BUFFER_SIZE 1518

std::string get_current_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// MAC 地址转字符串
std::string mac_to_str(const unsigned char *mac) {
    char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
    return std::string(buf);
}

void print_final_info(const unsigned char *buffer, ssize_t len) {
    const struct ether_header *eh = (const struct ether_header *)buffer;
    const struct iphdr *iph =
        (const struct iphdr *)(buffer + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, dst_ip, INET_ADDRSTRLEN);

    std::cout << "\n======================================================="
              << std::endl;
    std::cout << "[" << get_current_time()
              << " LOG: RECEIVER] 成功接收最终 IP 数据报 (" << len
              << " 字节):" << std::endl;
    std::cout << "  [L2] 源MAC地址: " << mac_to_str(eh->ether_shost)
              << " (来自路由器)" << std::endl;
    std::cout << "  [L2] 目的MAC地址: " << mac_to_str(eh->ether_dhost)
              << std::endl;
    std::cout << "  [L3] 源IP地址: " << src_ip << std::endl;
    std::cout << "  [L3] 目的IP地址: " << dst_ip << std::endl;
    std::cout << "  [L3] TTL: " << (int)iph->ttl << std::endl;
    std::cout << "  [L3] IP Checksum: 0x" << std::hex << ntohs(iph->check)
              << std::dec << " (应为有效)" << std::endl;

    if (iph->protocol == IPPROTO_UDP) {
        size_t ip_hdr_len = iph->ihl * 4;
        const struct udphdr *udph =
            (const struct udphdr *)(buffer + sizeof(struct ether_header) +
                                    ip_hdr_len);
        std::cout << "  [L4] UDP Src Port: " << ntohs(udph->source)
                  << std::endl;
        std::cout << "  [L4] UDP Dst Port: " << ntohs(udph->dest) << std::endl;

        const char *payload =
            (const char *)(buffer + sizeof(struct ether_header) + ip_hdr_len +
                           sizeof(struct udphdr));
        size_t payload_len = len - (sizeof(struct ether_header) + ip_hdr_len +
                                    sizeof(struct udphdr));
        std::cout << "  [DATA] 载荷内容: " << std::string(payload, payload_len)
                  << std::endl;
    }
    std::cout << "======================================================="
              << std::endl;
}

int main() {
    if (geteuid() != 0) {
        std::cerr << "错误: 必须使用 root 权限运行此程序 (sudo)." << std::endl;
        return 1;
    }

    int sockfd;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    unsigned char buffer[BUFFER_SIZE];

    // 1. 创建原始套接字 (监听所有以太网帧)
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("socket failed (need root)");
        return 1;
    }

    // 2. 获取接口索引
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    // 3. 绑定套接字到接口
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
        perror("bind failed");
        close(sockfd);
        return 1;
    }

    std::cout << "[" << get_current_time()
              << " LOG: RECEIVER] 目的主机启动，监听接口: " << INTERFACE_NAME
              << std::endl;
    std::cout << "目的主机 MAC: " << mac_to_str(RECEIVER_MAC) << std::endl;
    std::cout << "等待来自路由器的转发数据包..." << std::endl;

    while (1) {
        ssize_t received_bytes =
            recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);

        if (received_bytes <
            (ssize_t)(sizeof(struct ether_header) + sizeof(struct iphdr))) {
            if (received_bytes > 0)
                std::cerr << "收到过小的包，丢弃。" << std::endl;
            continue;
        }

        // 检查源 IP
        const struct iphdr *iph =
            (const struct iphdr *)(buffer + sizeof(struct ether_header));

        struct in_addr pkt_addr;
        pkt_addr.s_addr = iph->saddr;
        char pkt_src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt_addr, pkt_src_ip, INET_ADDRSTRLEN);

        struct in_addr ignore_addr;
        if (inet_pton(AF_INET, IGNORE_IP_STR, &ignore_addr) != 1) {
            continue;
        }

        if (pkt_addr.s_addr == ignore_addr.s_addr) {
            continue;
        }

        // 检查目的MAC是否是自己
        struct ether_header *eh = (struct ether_header *)buffer;
        if (memcmp(eh->ether_dhost, RECEIVER_MAC, ETH_ALEN) == 0) {
            print_final_info(buffer, received_bytes);
        } else {
            std::cerr << "[" << get_current_time()
                      << " LOG: RECEIVER] 收到发往其他主机的数据包，丢弃。" << std::endl;
        }
    }

    close(sockfd);
    return 0;
}