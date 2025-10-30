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
    if (argc != 3) {
        std::cerr << "用法: " << argv[0] << " <目标IP> <目标端口>" << std::endl;
        return 1;
    }

    const char* forward_ip = argv[1];
    int forward_port = std::atoi(argv[2]);

    if (forward_port <= 0 || forward_port > 65535) {
        std::cerr << "错误: 端口号无效。" << std::endl;
        return 1;
    }
    
    int sockfd;
    struct sockaddr_in forward_addr;
    char buffer[MAX_BUF_SIZE];
    
    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // 设置目标地址信息
    memset(&forward_addr, 0, sizeof(forward_addr));
    forward_addr.sin_family = AF_INET;
    forward_addr.sin_port = htons(forward_port); // 使用参数传入的目标端口
    if (inet_pton(AF_INET, forward_ip, &forward_addr.sin_addr) <= 0) { // 使用参数传入的目标IP
        perror("Invalid address/ Address not supported");
        close(sockfd);
        return 1;
    }

    std::cout << "--- UDP Sender 启动 [" << get_current_time() << "] ---" << std::endl;
    std::cout << "目标地址: " << forward_ip << ":" << forward_port << std::endl;
    std::cout << "请输入要发送的字符串 (输入 'exit' 退出):" << std::endl;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "exit") {
            break;
        }

        // 准备数据
        strncpy(buffer, line.c_str(), MAX_BUF_SIZE - 1);
        buffer[MAX_BUF_SIZE - 1] = '\0';
        int len = line.length();

        // 发送数据
        ssize_t sent_bytes = sendto(sockfd, buffer, len, 0,
                                    (const struct sockaddr*)&forward_addr, sizeof(forward_addr));

        if (sent_bytes < 0) {
            perror("Sendto failed");
            continue;
        }
        
        // 日志信息
        std::cout << "[" << get_current_time() << " LOG: SEND] 成功发送 " << sent_bytes << " 字节: '" << line << "'" << std::endl;
        std::cout << "继续输入: " << std::endl;
    }

    // 关闭套接字
    close(sockfd);
    std::cout << "--- UDP Sender 退出 ---" << std::endl;
    return 0;
}