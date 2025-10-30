// udp_recv.cpp (修改后)
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
    if (argc != 2) {
        std::cerr << "用法: " << argv[0] << " <监听端口>" << std::endl;
        return 1;
    }

    int listen_port = std::atoi(argv[1]);
    if (listen_port <= 0 || listen_port > 65535) {
        std::cerr << "错误: 端口号无效。" << std::endl;
        return 1;
    }

    int sockfd;
    struct sockaddr_in server_addr, forward_addr;
    socklen_t forward_len = sizeof(forward_addr);
    char buffer[MAX_BUF_SIZE];
    
    // 1. 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // 2. 设置本机监听地址信息
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port); // 使用参数传入的端口

    // 3. 绑定套接字到端口
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return 1;
    }

    std::cout << "--- UDP Receiver 启动 [" << get_current_time() << "] ---" << std::endl;
    std::cout << "监听端口: " << listen_port << std::endl;
    std::cout << "等待数据..." << std::endl;

    while (true) {
        // 4. 接收数据
        ssize_t n = recvfrom(sockfd, buffer, MAX_BUF_SIZE, 0,
                             (struct sockaddr *)&forward_addr, &forward_len);

        if (n < 0) {
            perror("Recvfrom failed");
            continue;
        }

        buffer[n] = '\0';
        char forward_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(forward_addr.sin_addr), forward_ip, INET_ADDRSTRLEN);
        int forward_port = ntohs(forward_addr.sin_port);

        // 5. 接收日志 (添加时间)
        std::cout << "\n[" << get_current_time() << " LOG: RECEIVE] 成功接收到 " << n << " 字节, 来自转发端 " << forward_ip << ":" << forward_port << std::endl;
        std::cout << "    内容: ===> '" << buffer << "' <===" << std::endl;
    }

    // 6. 关闭套接字
    close(sockfd);
    return 0;
}