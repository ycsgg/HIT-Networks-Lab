#include "HttpClient.h"
#include "ProxyPolicy.h"
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

using std::cerr;
using std::cout;
using std::endl;

// 定义代理服务器监听端口
constexpr int PROXY_PORT = 8888;

ProxyPolicy g_policy; // 全局策略实例

// Winsock 初始化
bool InitializeWinsock() {
    WSADATA wsaData;
    // 请求 Winsock 2.2 版本
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed." << endl;
        return false;
    }
    return true;
}

// Winsock 清理
void CleanupWinsock() {
    WSACleanup();
}

// 初始化全局策略
void initializePolicy() {
    // 允许本地用户访问
    g_policy.addAllowedUser("127.0.0.1");

    // 网站黑名单
    g_policy.addBlockedWebsite("baidu.com");

    // 钓鱼/引导规则
    g_policy.addPhishingRule("example.com", "http://www.baidu.com");
}

// 代理服务器主循环
void RunProxy() {
    // 1. 创建监听Socket
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        cerr << "Error creating socket: " << WSAGetLastError() << endl;
        return;
    }

    // 2. 配置地址
    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = htonl(INADDR_ANY); // 监听所有地址
    service.sin_port = htons(PROXY_PORT);        // 代理端口

    // 3. 绑定端口
    if (bind(listenSocket, (SOCKADDR *)&service, sizeof(service)) ==
        SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        return;
    }

    // 4. 开始监听
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Listen failed: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        return;
    }

    cout << "--- HTTP Proxy Server ---" << endl;
    cout << "Listening on port: " << PROXY_PORT << endl;
    cout << "-------------------------------" << endl;

    // 5. 接受连接主循环
    while (true) {
        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        // 阻塞等待客户端连接
        SOCKET clientSocket =
            accept(listenSocket, (SOCKADDR *)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "Accept failed: " << WSAGetLastError() << endl;
            continue;
        }

        char ipBuffer[INET_ADDRSTRLEN];
        // 将客户端IP地址转换为可读字符串
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ipBuffer, INET_ADDRSTRLEN);
        cout << "Client connected from: " << ipBuffer << endl;

        // 6. 为每个客户端连接启动一个新线程
        std::thread([clientSocket, clientAddr]() {
            HttpClient handler(clientSocket, &clientAddr);
            handler.Run(); // 在新线程中处理HTTP请求
            cout << "Client thread finished." << endl;
        }).detach(); // 分离线程，使其独立运行
    }

    closesocket(listenSocket);
}

int main() {
    if (!InitializeWinsock()) {
        return 1;
    }

    initializePolicy();

    RunProxy(); // 启动代理主循环

    CleanupWinsock();
    return 0;
}