// ip_send.cpp - 原始套接字发送端
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

const char* INTERFACE_NAME = "ens33"; 
// 主机A IP: 192.168.1.2
const char* SRC_IP_STR = "192.168.1.2";
// 目的IP: 192.168.1.4
const char* DST_IP_STR =  "192.168.1.4"; 
// 目的MAC 00:0c:29:c9:89:13
const unsigned char DEST_MAC[6] = {0x00, 0x0c, 0x29, 0xc9, 0x89, 0x13}; 
#define UDP_SRC_PORT 8888
#define UDP_DST_PORT 8888
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

int main() {
    if (geteuid() != 0) {
        std::cerr << "错误: 必须使用 root 权限运行此程序 (sudo)." << std::endl;
        return 1;
    }
    
    int sockfd;
    struct ifreq if_idx, if_mac;
    struct sockaddr_ll socket_address;
    unsigned char buffer[BUFFER_SIZE];
    const char msg[] = "UDP Payload from Host A (192.168.1.2)";
    size_t msg_len = strlen(msg);

    // 1. 创建原始套接字
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        return 1;
    }

    // 2. 获取接口索引和MAC地址
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        return 1;
    }
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        close(sockfd);
        return 1;
    }
    const unsigned char* src_mac = (const unsigned char*)if_mac.ifr_hwaddr.sa_data;
    
    // 3. 构造以太网帧
    memset(buffer, 0, BUFFER_SIZE);
    struct ether_header *eh = (struct ether_header *)buffer;
    
    // 目的MAC: 路由器的MAC
    memcpy(eh->ether_dhost, DEST_MAC, ETH_ALEN); 
    // 源MAC: 本机MAC
    memcpy(eh->ether_shost, src_mac, ETH_ALEN); 
    // 类型: IP (0x0800)
    eh->ether_type = htons(0x0800);

    // 4. 构造 IP 头
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    // 总长度 = IP头 + UDP头 + 数据长度
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + msg_len);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = htons(0x4000); // 不分片
    iph->ttl = 64; // 初始 TTL
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(SRC_IP_STR);
    iph->daddr = inet_addr(DST_IP_STR);
    // 计算 IP 校验和
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // 5. 构造 UDP 头
    struct udphdr *udph =
        (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    udph->source = htons(UDP_SRC_PORT);
    udph->dest = htons(UDP_DST_PORT);
    // UDP 长度 = UDP头 + 数据长度
    udph->len = htons(sizeof(struct udphdr) + msg_len);
    udph->check = 0; // 校验和设为0

    // 6. 填充数据
    unsigned char *data = buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(data, msg, msg_len);
    
    // 7. 设置 socket 地址结构
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, DEST_MAC, ETH_ALEN);

    // 8. 发送数据包
    int total_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + msg_len;
    
    // 日志
    std::cout << "[" << get_current_time() << " LOG: SENDER] 开始发送数据包..." << std::endl;
    std::cout << "  [L2] Src MAC: " << std::hex << (int)src_mac[0] << ":" << (int)src_mac[1] << ":" << (int)src_mac[2] << ":" << (int)src_mac[3] << ":" << (int)src_mac[4] << ":" << (int)src_mac[5] << std::dec << std::endl;
    std::cout << "  [L2] Dst MAC:  (Router)" << std::endl;
    std::cout << "  [L3] Src IP: " << SRC_IP_STR << std::endl;
    std::cout << "  [L3] Dst IP: " << DST_IP_STR << std::endl;
    std::cout << "  [L3] TTL: " << (int)iph->ttl << std::endl;
    std::cout << "  [INFO] 总长度: " << total_len << " 字节" << std::endl;


    if (sendto(sockfd, buffer, total_len, 0, (struct sockaddr *)&socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto failed");
        close(sockfd);
        return 1;
    }
    
    std::cout << "[" << get_current_time() << " LOG: SENDER] 成功发送 " << total_len << " 字节到下一跳路由器" << std::endl;
    
    close(sockfd);
    return 0;
}