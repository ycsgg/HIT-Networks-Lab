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

#define BUFFER_SIZE 1518
#define ETH_ALEN    6

// 接口信息结构体
struct RouterInterface {
    const char *if_name;
    const char *ip_addr_str;
    const unsigned char mac_addr[ETH_ALEN];
    int if_index;           // 接口索引
    in_addr_t network_addr; // 网络地址 (192.168.10.0)
    in_addr_t netmask;      // 子网掩码 (255.255.255.0)
};

// 转发表项
struct RouteEntry {
    in_addr_t dest_network;
    in_addr_t netmask;
    const unsigned char next_hop_mac[ETH_ALEN]; // 下一跳的 MAC 地址
    const char *outgoing_if_name;               // 出接口名称
};

const unsigned char MAC_ENS33[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x32, 0xa9, 0xb6};
const unsigned char MAC_ENS37[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x32, 0xa9, 0xc0};

const unsigned char NEXT_HOP_MAC_TO_20_NET[ETH_ALEN] = {0x00, 0x0c, 0x29,
                                                        0xda, 0x3f, 0x0f};
const unsigned char NEXT_HOP_MAC_TO_10_NET[ETH_ALEN] = {0x00, 0x0c, 0x29,
                                                        0x52, 0xc2, 0xba};

// 路由器接口配置
RouterInterface interfaces[] = {{"ens33",
                                 "192.168.10.10",
                                 {0x00, 0x0c, 0x29, 0x32, 0xa9, 0xb6},
                                 0,
                                 0,
                                 inet_addr("255.255.255.0")},
                                {"ens37",
                                 "192.168.20.10",
                                 {0x00, 0x0c, 0x29, 0x32, 0xa9, 0xc0},
                                 0,
                                 0,
                                 inet_addr("255.255.255.0")}};

// 静态路由表
// 路由表项：(目的网络, 子网掩码, 下一跳 MAC, 出接口)
RouteEntry routing_table[] = {
    // 路由到 192.168.20.0/24
    {inet_addr("192.168.20.0"),
     inet_addr("255.255.255.0"),
     {0x00, 0x0c, 0x29, 0xda, 0x3f, 0x0f},
     "ens37"},
    // 路由到 192.168.10.0/24
    {inet_addr("192.168.10.0"),
     inet_addr("255.255.255.0"),
     {0x00, 0x0c, 0x29, 0x52, 0xc2, 0xba},
     "ens33"},
};

// --- 通用函数 (与之前版本相同) ---

std::string get_current_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

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

std::string mac_to_str(const unsigned char *mac) {
    char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
    return std::string(buf);
}

void print_packet_info(const unsigned char *buffer, ssize_t len,
                       const char *stage, const char *iface) {
    const struct ether_header *eh = (const struct ether_header *)buffer;
    const struct iphdr *iph =
        (const struct iphdr *)(buffer + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, dst_ip, INET_ADDRSTRLEN);

    std::cout << "\n[" << get_current_time() << " LOG: " << stage
              << "] IFACE: " << iface << ", 数据包 (" << len
              << " 字节):" << std::endl;
    std::cout << "  [L2] Src MAC: " << mac_to_str(eh->ether_shost) << std::endl;
    std::cout << "  [L2] Dst MAC: " << mac_to_str(eh->ether_dhost) << std::endl;
    std::cout << "  [L3] Src IP: " << src_ip << std::endl;
    std::cout << "  [L3] Dst IP: " << dst_ip << std::endl;
    std::cout << "  [L3] TTL: " << (int)iph->ttl << std::endl;
    std::cout << "  [L3] IP Checksum: 0x" << std::hex << ntohs(iph->check)
              << std::dec << std::endl;
}

// 获取接口的索引和 MAC 地址
bool init_interface(int sockfd, RouterInterface &iface) {
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, iface.if_name, IFNAMSIZ - 1);

    // 获取接口索引
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror(
            ("SIOCGIFINDEX failed for " + std::string(iface.if_name)).c_str());
        return false;
    }
    iface.if_index = if_idx.ifr_ifindex;

    // 验证配置的 MAC 地址
    struct ifreq if_mac;
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, iface.if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror(
            ("SIOCGIFHWADDR failed for " + std::string(iface.if_name)).c_str());
        return false;
    }
    // 计算网络地址
    iface.network_addr = inet_addr(iface.ip_addr_str) & iface.netmask;

    return true;
}

/**
 * 查表转发逻辑
 */
const RouteEntry *find_route(in_addr_t dest_ip) {
    const RouteEntry *best_match = nullptr;
    in_addr_t best_netmask = 0;

    for (const auto &entry : routing_table) {
        // 计算目标 IP 对应的网络地址
        in_addr_t dest_net = dest_ip & entry.netmask;

        // 如果匹配到目标网络
        if (dest_net == entry.dest_network) {
            // 这是简化版的最长前缀匹配：如果有更长的掩码
            // (即更精确的匹配)，则更新
            if (entry.netmask >= best_netmask) {
                best_match = &entry;
                best_netmask = entry.netmask;
            }
        } else if (entry.dest_network == inet_addr("0.0.0.0") &&
                   entry.netmask == inet_addr("0.0.0.0")) {
            // 处理默认路由 (0.0.0.0/0)
            if (best_match == nullptr || best_netmask == 0) {
                best_match = &entry;
                best_netmask = 0;
            }
        }
    }
    return best_match;
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        std::cerr << "错误: 必须使用 root 权限运行此程序 (sudo)." << std::endl;
        return 1;
    }

    // 检查命令行参数
    if (argc != 1) {
        std::cerr << "用法: " << argv[0] << " (无需参数)" << std::endl;
        return 1;
    }

    int sockfd;

    // 1. 创建原始套接字
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket failed (need root)");
        return 1;
    }

    // 2. 初始化接口信息
    for (auto &iface : interfaces) {
        if (!init_interface(sockfd, iface)) {
            close(sockfd);
            return 1;
        }
    }

    // 3. 打印配置
    std::cout << "--- 双网口路由器配置 ---" << std::endl;
    for (const auto &iface : interfaces) {
        char net_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iface.network_addr, net_str, INET_ADDRSTRLEN);
        std::cout << "接口: " << iface.if_name << " (Index: " << iface.if_index
                  << ")"
                  << ", IP: " << iface.ip_addr_str
                  << ", MAC: " << mac_to_str(iface.mac_addr)
                  << ", Net: " << net_str << std::endl;
    }
    std::cout << "------------------------" << std::endl;
    std::cout << "等待数据包..." << std::endl;

    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        // 4. 接收数据包 (L2 帧)
        struct sockaddr_ll from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t received_bytes =
            recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                     (struct sockaddr *)&from_addr, &from_len);

        if (received_bytes <
            (ssize_t)(sizeof(struct ether_header) + sizeof(struct iphdr))) {
            if (received_bytes > 0)
                std::cerr << "收到过小的包，丢弃。" << std::endl;
            continue;
        }

        struct ether_header *eh = (struct ether_header *)buffer;
        struct iphdr *ip_hdr =
            (struct iphdr *)(buffer + sizeof(struct ether_header));

        // 5. 确定数据包来自哪个接口
        RouterInterface *incoming_iface = nullptr;
        for (auto &iface : interfaces) {
            if (iface.if_index == from_addr.sll_ifindex) {
                incoming_iface = &iface;
                break;
            }
        }
        if (incoming_iface == nullptr)
            continue; 

        // 6. 检查目的 MAC 是否是该接口的 MAC
        if (memcmp(eh->ether_dhost, incoming_iface->mac_addr, ETH_ALEN) != 0) {
            continue;
        }

        // 7. 检查 IP 头部，判断是否是发给路由器自己的
        in_addr_t router_ip_int = inet_addr(incoming_iface->ip_addr_str);
        if (ip_hdr->daddr == router_ip_int) {
            continue;
        }

        // 8. 打印接收信息
        print_packet_info(buffer, received_bytes, "RECV",
                          incoming_iface->if_name);

        // 9. 转发逻辑

        // a. TTL 检查
        if (ip_hdr->ttl <= 1) {
            std::cerr << "[" << get_current_time() << " LOG: DROP] TTL 过期 ("
                      << (int)ip_hdr->ttl << ")，丢弃数据包。" << std::endl;
            continue;
        }

        // b. 查路由表
        const RouteEntry *route = find_route(ip_hdr->daddr);

        if (route == nullptr) {
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_hdr->daddr, dest_ip, INET_ADDRSTRLEN);
            std::cerr << "[" << get_current_time() << " LOG: DROP] 目的 IP ("
                      << dest_ip << ") 未找到路由，丢弃数据包。" << std::endl;
            continue;
        }

        // c. 确定出接口信息
        RouterInterface *outgoing_iface = nullptr;
        for (auto &iface : interfaces) {
            if (strcmp(iface.if_name, route->outgoing_if_name) == 0) {
                outgoing_iface = &iface;
                break;
            }
        }
        if (outgoing_iface == nullptr) {
            std::cerr << "[" << get_current_time()
                      << " LOG: DROP] 路由表指定的出接口 ("
                      << route->outgoing_if_name << ") 无效，丢弃。"
                      << std::endl;
            continue;
        }

        // d. 修改 L3 头部
        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check =
            checksum((unsigned short *)ip_hdr, sizeof(struct iphdr));

        // e. 修改 L2 头部
        memcpy(eh->ether_shost, outgoing_iface->mac_addr,
               ETH_ALEN); // Src MAC: 出接口的 MAC
        memcpy(eh->ether_dhost, route->next_hop_mac,
               ETH_ALEN); // Dst MAC: 下一跳的 MAC

        // 10. 打印转发信息
        print_packet_info(buffer, received_bytes, "FORWARD",
                          outgoing_iface->if_name);

        // 11. 重新发送数据包 (通过指定的出接口)
        struct sockaddr_ll socket_send_addr;
        memset(&socket_send_addr, 0, sizeof(struct sockaddr_ll));
        socket_send_addr.sll_ifindex = outgoing_iface->if_index;
        socket_send_addr.sll_halen = ETH_ALEN;
        memcpy(socket_send_addr.sll_addr, route->next_hop_mac, ETH_ALEN);

        if (sendto(sockfd, buffer, received_bytes, 0,
                   (struct sockaddr *)&socket_send_addr,
                   sizeof(struct sockaddr_ll)) < 0) {
            perror("sendto forward failed");
        } else {
            std::cout << "[" << get_current_time() << " LOG: FORWARD] 成功转发 "
                      << received_bytes
                      << " 字节到下一跳: " << mac_to_str(route->next_hop_mac)
                      << std::endl;
        }
    }

    close(sockfd);
    return 0;
}