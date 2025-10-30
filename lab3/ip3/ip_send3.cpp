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
const char* SRC_IP_STR = "192.168.10.2";
const char* DST_IP_STR =  "192.168.20.2"; 
const unsigned char DEST_MAC[6] = {0x00, 0x0c, 0x29, 0x32, 0xa9, 0xb6}; 
#define UDP_SRC_PORT 8888
#define UDP_DST_PORT 8888
#define BUFFER_SIZE  1518
#define ETH_ALEN 6

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
    const char msg[] = "Hello, this is a test message."; 
    size_t msg_len = strlen(msg);

    // 创建原始套接字 
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        return 1;
    }

    // 获取接口索引和MAC地址
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
    
    // 绑定套接字到接口
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind failed");
        close(sockfd);
        return 1;
    }


    // 构造和发送数据包 (L2 帧)
    
    // 构造 L2 头部
    memset(buffer, 0, BUFFER_SIZE);
    struct ether_header *eh = (struct ether_header *)buffer;
    memcpy(eh->ether_dhost, DEST_MAC, ETH_ALEN); 
    memcpy(eh->ether_shost, src_mac, ETH_ALEN); 
    eh->ether_type = htons(0x0800); // IP

    // 构造 L3 头部
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
    iph->ihl = 5; iph->version = 4; iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + msg_len);
    iph->id = htonl(rand() % 65535); iph->frag_off = htons(0x4000); 
    iph->ttl = 64; iph->protocol = IPPROTO_UDP; iph->check = 0;
    iph->saddr = inet_addr(SRC_IP_STR); iph->daddr = inet_addr(DST_IP_STR);
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // 构造 L4 头部和 Payload
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    udph->source = htons(UDP_SRC_PORT); udph->dest = htons(UDP_DST_PORT);
    udph->len = htons(sizeof(struct udphdr) + msg_len); udph->check = 0;
    unsigned char *data = buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(data, msg, msg_len);
    
    // 设置发送地址
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, DEST_MAC, ETH_ALEN);

    // 发送
    int total_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + msg_len;
    std::cout << "[" << get_current_time() << " LOG: SENDER] 开始发送数据包..." << std::endl;
    std::cout << "  [L3] Src IP: " << SRC_IP_STR << ", Dst IP: " << DST_IP_STR << std::endl;
    std::cout << "  [L4] Payload: " << msg << std::endl;

    if (sendto(sockfd, buffer, total_len, 0, (struct sockaddr *)&socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto failed");
        close(sockfd);
        return 1;
    }
    std::cout << "[" << get_current_time() << " LOG: SENDER] 成功发送 " << total_len << " 字节到下一跳路由器" << std::endl;
    
    
    std::cout << "\n[" << get_current_time() << " LOG: SENDER] 等待来自 " << DST_IP_STR << " 的回复..." << std::endl;
    in_addr_t expected_reply_ip = inet_addr(DST_IP_STR);
    in_addr_t my_ip = inet_addr(SRC_IP_STR);

    while (1) {
        ssize_t received_bytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);

        if (received_bytes < (ssize_t)(sizeof(struct ether_header) + sizeof(struct iphdr))) {
            continue;
        }
        
        struct ether_header *eh_recv = (struct ether_header *)buffer;
        struct iphdr *ip_hdr_recv = (struct iphdr *)(buffer + sizeof(struct ether_header));
        
        // 1. 检查目的 MAC 是否是自己
        if (memcmp(eh_recv->ether_dhost, src_mac, ETH_ALEN) != 0) {
            continue;
        }

        // 2. 检查目的 IP 是否是自己 (192.168.10.2)
        if (ip_hdr_recv->daddr != my_ip) {
            continue;
        }
        
        // 3. 检查源 IP 是否是期望的回复方 (192.168.20.2)
        if (ip_hdr_recv->saddr == expected_reply_ip) {
            
            // 成功接收回复
            std::cout << "\n=======================================================" << std::endl;
            std::cout << "[" << get_current_time() << " LOG: SENDER/RECV] 成功收到回复数据报 (" << received_bytes << " 字节):" << std::endl;
            
            char src_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr_recv->saddr, src_ip_str, INET_ADDRSTRLEN);

            std::cout << "  [L3] 源IP地址: " << src_ip_str << std::endl;
            
            if (ip_hdr_recv->protocol == IPPROTO_UDP) {
                 size_t ip_hdr_len = ip_hdr_recv->ihl * 4;
                 const struct udphdr *udph_recv =
                     (const struct udphdr *)(buffer + sizeof(struct ether_header) + ip_hdr_len);
                 const char *payload =
                     (const char *)(buffer + sizeof(struct ether_header) + ip_hdr_len +
                                    sizeof(struct udphdr));
                 size_t payload_len = received_bytes - (sizeof(struct ether_header) + ip_hdr_len +
                                        sizeof(struct udphdr));
                 // 打印载荷
                 std::cout << "  [DATA] 回复内容: " << std::string(payload, std::min((size_t)payload_len, (size_t)BUFFER_SIZE)) << std::endl; 
            }
            std::cout << "=======================================================" << std::endl;
            break; // 退出循环
        }
    }
    
    close(sockfd);
    return 0;
}