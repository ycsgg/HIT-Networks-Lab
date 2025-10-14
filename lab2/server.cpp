#include "GBNmanager.h"
#include "../logger/logger.h"
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// 定义端口和地址
#define SERVER_LOCAL_PORT 8889
#define TUNNEL_PORT       8888
#define TUNNEL_IP         "127.0.0.1"

using logger::error;
using logger::info;
using std::endl;
using std::string;
using std::vector;

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        error << "WSAStartup failed." << endl;
        return 1;
    }

    SOCKET serverSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVER_LOCAL_PORT);
    if (bind(serverSock, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) ==
        SOCKET_ERROR) {
        error << "bind failed: " << WSAGetLastError() << endl;
        closesocket(serverSock);
        WSACleanup();
        return 1;
    }

    // 设置目标地址 (Tunnel 地址)
    sockaddr_in tunnelAddr;
    tunnelAddr.sin_family = AF_INET;
    InetPton(AF_INET, TUNNEL_IP, &tunnelAddr.sin_addr);
    tunnelAddr.sin_port = htons(TUNNEL_PORT);

    GBNManager gbnManager(serverSock, tunnelAddr, "SERVER");

    info << "--------------------------------------------------------" << endl;
    info << "Server (GBN Manager) is running on port " << SERVER_LOCAL_PORT
         << endl;
    info << "--------------------------------------------------------" << endl;

    // 模拟应用层数据源
    vector<string> messages_to_send = {
        "S_MSG_01: Hello Client!",  "S_MSG_02: This is Server.",
        "S_MSG_03: GBN A",          "S_MSG_04: GBN B",
        "S_MSG_05: GBN C",          "S_MSG_06: Check reliable transmission.",
        "S_MSG_07: Final Message.",
    };
    int next_msg_index = 0;

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSock, &readfds);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10 * 1000; // 10毫秒

        if (select(0, &readfds, NULL, NULL, &tv) > 0) {
            Packet received_packet;
            sockaddr_in senderAddr;
            int senderAddrLen = sizeof(senderAddr);
            int bytes = recvfrom(serverSock, (char *)&received_packet,
                                 sizeof(received_packet), 0,
                                 (SOCKADDR *)&senderAddr, &senderAddrLen);

            if (bytes > 0) {
                gbnManager.processReceivedPacket(received_packet, senderAddr);
            }
        }

        // 尝试从应用层获取数据并发送 (Server -> Client)
        if (next_msg_index < messages_to_send.size()) {
            const string &msg = messages_to_send[next_msg_index];

            // 调用 GBN Manager 的发送方法
            if (gbnManager.sendData(msg.c_str(), msg.length())) {
                next_msg_index++; // 成功发送或放入窗口，则准备发送下一个消息
            }
        }

        // 检查超时并重传
        gbnManager.checkTimeoutAndRetransmit();
    }

    closesocket(serverSock);
    WSACleanup();
    return 0;
}