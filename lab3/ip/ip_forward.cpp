// ip_forward.cpp - 路由器/转发端
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
/**
192.168.1.2 00:0c:29:52:c2:ba
192.168.1.3 00:0c:29:c9:89:13
192.168.1.4 00:0c:29:05:82:fe
192.168.1.5 00:0c:29:ee:bb:99
192.168.1.6 00:0c:29:1c:6f:cf
**/
const char* INTERFACE_NAME = "ens33";

const char* SRC_IP_STR = "192.168.1.2";
// 路由器接口 MAC 地址 00:0c:29:c9:89:13
const unsigned char ROUTER_MAC[6] = {0x00, 0x0c, 0x29, 0xc9, 0x89, 0x13};
// 目的主机 MAC 地址 00:0c:29:05:82:fe
const unsigned char DEST_HOST_MAC[6] = {0x00, 0x0c, 0x29, 0x05, 0x82, 0xfe};
#define BUFFER_SIZE  1518

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

void print_packet_info(const unsigned char* buffer, ssize_t len, const char* stage) {
    const struct ether_header *eh = (const struct ether_header *)buffer;
    const struct iphdr *iph = (const struct iphdr *)(buffer + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, dst_ip, INET_ADDRSTRLEN);

    std::cout << "\n[" << get_current_time() << " LOG: FORWARD/" << stage << "] 收到/转发 IP 数据报 (" << len << " 字节):" << std::endl;
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
         std::cout << "  [L4] Payload: " << (const char*)(buffer + sizeof(struct ether_header) + (iph->ihl * 4) + sizeof(struct udphdr)) << std::endl;
    }
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
    // ETH_P_IP: 仅接收 IP 协议帧
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
    if (bind(sockfd, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind failed");
        close(sockfd);
        return 1;
    }
    
    std::cout << "[" << get_current_time() << " LOG: FORWARD] 路由器启动，监听接口: " << INTERFACE_NAME << std::endl;
    std::cout << "路由器 MAC: " << mac_to_str(ROUTER_MAC) << std::endl;
    std::cout << "等待数据包..." << std::endl;

    while (1) {
        // 4. 接收数据包 (L2 帧)
        ssize_t received_bytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);

        if (received_bytes < (ssize_t)(sizeof(struct ether_header) + sizeof(struct iphdr))) {
            if (received_bytes > 0) std::cerr << "收到过小的包，丢弃。" << std::endl;
            continue;
        }

        // 5. 解析头部并检查目的 MAC
        struct ether_header *eh = (struct ether_header *)buffer;
        
        // 检查目的MAC是否是路由器自己（即数据包是给路由器的）
        if (memcmp(eh->ether_dhost, ROUTER_MAC, ETH_ALEN) != 0) {
            // 收到非发给自己的帧，可能是广播或混杂模式下的其他流量，忽略
            continue;
        }

        // 检查源 IP 是否为配置的 SRC_IP_STR
        struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct ether_header));
        struct in_addr expected_src;
        if (inet_pton(AF_INET, SRC_IP_STR, &expected_src) != 1) {
            std::cerr << "[" << get_current_time() << " LOG: FORWARD] 无法解析配置的源 IP: " << SRC_IP_STR << std::endl;
            continue;
        }
        if (ip_hdr->saddr != expected_src.s_addr) {
            continue;
        }

        // 6. 打印接收信息
        print_packet_info(buffer, received_bytes, "RECV");

        // 7. 转发逻辑
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));

        // b. 检查 TTL
        if (iph->ttl <= 1) {
            std::cerr << "[" << get_current_time() << " LOG: FORWARD] TTL 过期 (" << (int)iph->ttl << ")，丢弃数据包。" << std::endl;
            continue;
        }

        // c. 修改 TTL
        iph->ttl--;

        // d. 重新计算 IP 校验和 (必须先清零)
        iph->check = 0; 
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        // e. 修改 L2 头部 (更改源MAC和目的MAC为下一跳)
        // Src MAC: 路由器 MAC
        memcpy(eh->ether_shost, ROUTER_MAC, ETH_ALEN); 
        // Dst MAC: 目的主机 B 的 MAC
        memcpy(eh->ether_dhost, DEST_HOST_MAC, ETH_ALEN); 

        // 8. 打印转发信息
        print_packet_info(buffer, received_bytes, "FORWARD");

        // 9. 重新发送数据包 (L2 帧)
        // 重新设置 socket 地址结构，用于下一跳发送
        memset(&socket_address, 0, sizeof(struct sockaddr_ll));
        socket_address.sll_ifindex = if_idx.ifr_ifindex;
        socket_address.sll_halen = ETH_ALEN;
        memcpy(socket_address.sll_addr, DEST_HOST_MAC, ETH_ALEN);

        if (sendto(sockfd, buffer, received_bytes, 0, (struct sockaddr *)&socket_address,
                   sizeof(struct sockaddr_ll)) < 0) {
            perror("sendto forward failed");
        } else {
            std::cout << "[" << get_current_time() << " LOG: FORWARD] 成功转发 " << received_bytes << " 字节到目的主机" << std::endl;
        }
    }

    close(sockfd);
    return 0;
}