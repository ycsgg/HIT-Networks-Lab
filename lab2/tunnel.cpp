#include "../logger/logger.h"
#include "packet.h"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define LOCALHOST_IP "127.0.0.1"

constexpr int TUNNEL_PORT = 8888;
constexpr int SERVER_PORT = 8887;
constexpr int CLIENT_PORT = 8889;
constexpr double LOSS_RATE = 0.3; // 模拟丢包概率
using logger::error;
using logger::info;
using logger::warn;
using std::endl;

int main() {
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        error << "WSAStartup failed." << endl;
        return 1;
    }

    // 创建 UDP 套接字
    SOCKET tunnelSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (tunnelSock == INVALID_SOCKET) {
        error << "Socket creation failed." << endl;
        WSACleanup();
        return 1;
    }

    // 绑定套接字到指定端口
    sockaddr_in tunnelAddr;
    tunnelAddr.sin_family = AF_INET;
    tunnelAddr.sin_addr.s_addr = INADDR_ANY;
    tunnelAddr.sin_port = htons(TUNNEL_PORT);

    if (bind(tunnelSock, (sockaddr *)&tunnelAddr, sizeof(tunnelAddr)) ==
        SOCKET_ERROR) {
        error << "Bind failed." << endl;
        closesocket(tunnelSock);
        WSACleanup();
        return 1;
    }

    info << "Tunnel is running on port " << TUNNEL_PORT << endl;
    info << "Forwarding between Server (port " << SERVER_PORT
         << ") and Client (port " << CLIENT_PORT << ")" << endl;
    info << "Simulated packet loss rate: " << LOSS_RATE * 100 << "%" << endl;

    srand(static_cast<unsigned int>(time(0)));

    sockaddr_in clientAddr, serverAddr;
    int clientAddrLen = sizeof(clientAddr);
    int serverAddrLen = sizeof(serverAddr);

    while (true) {
        Packet packet;
        sockaddr_in senderAddr;
        int senderAddrLen = sizeof(senderAddr);

        // 接收数据包
        int bytesReceived =
            recvfrom(tunnelSock, (char *)&packet, sizeof(packet), 0,
                     (SOCKADDR *)&senderAddr, &senderAddrLen);

        sockaddr_in targetAddr;
        std::string sender, target;
        if (ntohs(senderAddr.sin_port) == CLIENT_PORT) {
            // 从 Client 发来，转发给 Server
            targetAddr.sin_family = AF_INET;
            InetPton(AF_INET, LOCALHOST_IP, &targetAddr.sin_addr);
            targetAddr.sin_port = htons(SERVER_PORT);
            sender = "Client";
            target = "Server";
        } else {
            // 从 Server 或其他地方发来，转发给 Client
            targetAddr.sin_family = AF_INET;
            InetPton(AF_INET, LOCALHOST_IP, &targetAddr.sin_addr);
            targetAddr.sin_port = htons(CLIENT_PORT);
            sender = "Server";
            target = "Client";
        }

        if ((double)rand() / RAND_MAX < LOSS_RATE) {
            warn << "Packet dropped! Seq/Ack: " << packet.seq_num << "/"
                 << packet.ack_num << " from " << sender << " to " << target
                 << endl;
            continue; // 丢包
        }

        // 转发数据包
        sendto(tunnelSock, (const char *)&packet, bytesReceived, 0,
               (SOCKADDR *)&targetAddr, sizeof(targetAddr));
        info << "Packet forwarded Seq/Ack: " << packet.seq_num << "/"
             << packet.ack_num << " from " << sender << " to " << target
             << endl;
    }
}