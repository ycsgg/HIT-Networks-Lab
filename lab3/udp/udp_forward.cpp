// udp_forward.cpp (修改后)
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono> 
#include <ctime>    
#include <iomanip> 
#include <sstream>
#include <cstdlib> 

const int MAX_BUF_SIZE = 1024;

std::string get_current_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "用法: " << argv[0] << " <监听端口> <目标IP> <目标端口>" << std::endl;
        return 1;
    }

    int listen_port = std::atoi(argv[1]);
    const char* recv_ip = argv[2];
    int recv_port = std::atoi(argv[3]);

    if (listen_port <= 0 || listen_port > 65535 || recv_port <= 0 || recv_port > 65535) {
        std::cerr << "错误: 端口号无效。" << std::endl;
        return 1;
    }

    int sockfd;
    struct sockaddr_in server_addr, recv_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[MAX_BUF_SIZE];
    
    // 1. 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // 2. 设置本机监听地址信息
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // 监听所有地址
    server_addr.sin_port = htons(listen_port); // 使用参数传入的监听端口

    // 3. 绑定套接字到端口
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    // 4. 设置目标转发地址信息 (udp_recv)
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(recv_port); // 使用参数传入的目标端口
    if (inet_pton(AF_INET, recv_ip, &recv_addr.sin_addr) <= 0) { // 使用参数传入的目标IP
        perror("Invalid forward address");
        close(sockfd);
        return 1;
    }

    std::cout << "--- UDP Forwarder 启动 [" << get_current_time() << "] ---" << std::endl;
    std::cout << "监听端口: " << listen_port << std::endl;
    std::cout << "转发目标: " << recv_ip << ":" << recv_port << std::endl;
    
    while (true) {
        // 5. 接收数据
        ssize_t n = recvfrom(sockfd, buffer, MAX_BUF_SIZE, 0,
                             (struct sockaddr *)&client_addr, &client_len);

        if (n < 0) {
            perror("Recvfrom failed");
            continue;
        }

        buffer[n] = '\0';
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        // 6. 接收日志 (添加时间)
        std::cout << "\n[" << get_current_time() << " LOG: RECV] 接收到 " << n << " 字节, 来自 " << client_ip << ":" << client_port << std::endl;
        std::cout << "    内容: '" << buffer << "'" << std::endl;

        // 7. 转发数据
        ssize_t sent_bytes = sendto(sockfd, buffer, n, 0,
                                    (const struct sockaddr*)&recv_addr, sizeof(recv_addr));

        if (sent_bytes < 0) {
            perror("Forward sendto failed");
            continue;
        }

        // 8. 转发日志 (添加时间)
        std::cout << "[" << get_current_time() << " LOG: FORWARD] 成功转发 " << sent_bytes << " 字节 到 " << recv_ip << ":" << recv_port << std::endl;
    }

    // 9. 关闭套接字
    close(sockfd);
    return 0;
}