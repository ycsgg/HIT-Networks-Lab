#include <algorithm> // for std::min
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
const char *RECEIVER_IP_STR = "192.168.20.2";
const char *IGNORE_IP_STR = "192.168.20.1";
const unsigned char RECEIVER_MAC[6] = {0x00, 0x0c, 0x29, 0xda, 0x3f, 0x0f};
const unsigned char ROUTER_20_MAC[6] = {0x00, 0x0c, 0x29, 0x32, 0xa9, 0xc0};
#define UDP_SRC_PORT 8888
#define UDP_DST_PORT 8888
#define BUFFER_SIZE  1518
#define ETH_ALEN     6

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
              << std::endl;
    std::cout << "  [L3] 源IP地址: " << src_ip << std::endl;
    std::cout << "  [L3] 目的IP地址: " << dst_ip << std::endl;

    if (iph->protocol == IPPROTO_UDP) {
        size_t ip_hdr_len = iph->ihl * 4;
        const struct udphdr *udph =
            (const struct udphdr *)(buffer + sizeof(struct ether_header) +
                                    ip_hdr_len);
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

// 新增发送回复函数
void send_reply(int sockfd, int if_index, const unsigned char *src_mac,
                const struct iphdr *in_iph, const char *reply_msg) {

    unsigned char reply_buffer[BUFFER_SIZE];
    size_t reply_msg_len = strlen(reply_msg);
    int total_len = sizeof(struct ether_header) + sizeof(struct iphdr) +
                    sizeof(struct udphdr) + reply_msg_len;

    // 1. 构造以太网帧
    memset(reply_buffer, 0, BUFFER_SIZE);
    struct ether_header *eh = (struct ether_header *)reply_buffer;

    // 目的MAC: 路由器 20-net 接口 MAC
    memcpy(eh->ether_dhost, ROUTER_20_MAC, ETH_ALEN);
    // 源MAC: 本机 MAC
    memcpy(eh->ether_shost, src_mac, ETH_ALEN);
    // 类型: IP (0x0800)
    eh->ether_type = htons(0x0800);

    // 2. 构造 IP 头
    struct iphdr *iph =
        (struct iphdr *)(reply_buffer + sizeof(struct ether_header));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len =
        htons(sizeof(struct iphdr) + sizeof(struct udphdr) + reply_msg_len);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = htons(0x4000); // 不分片
    iph->ttl = 64;                 // 初始 TTL
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    // 源IP: 接收方 IP (192.168.20.2)
    iph->saddr = inet_addr(RECEIVER_IP_STR);
    // 目的IP: 发送方 IP (in_iph->saddr)
    iph->daddr = in_iph->saddr;
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // 3. 构造 UDP 头
    struct udphdr *udph =
        (struct udphdr *)(reply_buffer + sizeof(struct ether_header) +
                          sizeof(struct iphdr));
    udph->source = htons(UDP_SRC_PORT);
    udph->dest = htons(UDP_DST_PORT);
    udph->len = htons(sizeof(struct udphdr) + reply_msg_len);
    udph->check = 0;

    // 4. 填充数据
    unsigned char *data = reply_buffer + sizeof(struct ether_header) +
                          sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(data, reply_msg, reply_msg_len);

    // 5. 设置 socket 地址结构
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_index;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, ROUTER_20_MAC, ETH_ALEN);

    // 6. 发送
    std::cout << "\n[" << get_current_time()
              << " LOG: SENDER] 发送回复数据包..." << std::endl;
    if (sendto(sockfd, reply_buffer, total_len, 0,
               (struct sockaddr *)&socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto reply failed");
    } else {
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in_iph->saddr, dst_ip_str, INET_ADDRSTRLEN);
        std::cout << "[" << get_current_time()
                  << " LOG: SENDER] 成功发送回复到 " << dst_ip_str << std::endl;
    }
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

    // 1. 创建原始套接字 (监听 IP 帧)
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("socket failed (need root)");
        return 1;
    }

    // 2. 获取接口索引和MAC地址
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX failed");
        close(sockfd);
        return 1;
    }

    // 获取本机MAC，用于回复
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR failed");
        close(sockfd);
        return 1;
    }
    const unsigned char *src_mac =
        (const unsigned char *)if_mac.ifr_hwaddr.sa_data;

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

        // 检查目的MAC是否是自己
        struct ether_header *eh = (struct ether_header *)buffer;
        if (memcmp(eh->ether_dhost, RECEIVER_MAC, ETH_ALEN) != 0) {
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

        print_final_info(buffer, received_bytes);

        // **发送回复**
        const char reply_msg[] = "Hello! Got your message loud and clear.";
        send_reply(sockfd, if_idx.ifr_ifindex, src_mac, iph, reply_msg);
    }

    close(sockfd);
    return 0;
}