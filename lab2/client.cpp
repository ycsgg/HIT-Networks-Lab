#include "../logger/logger.h"
#include "GBNmanager.h"
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// 定义端口和地址
#define CLIENT_LOCAL_PORT 8887
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

    SOCKET clientSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (clientSock == INVALID_SOCKET) {
        error << "socket failed: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in clientAddr;
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = INADDR_ANY;
    clientAddr.sin_port = htons(CLIENT_LOCAL_PORT);

    if (bind(clientSock, (SOCKADDR *)&clientAddr, sizeof(clientAddr)) ==
        SOCKET_ERROR) {
        error << "bind failed: " << WSAGetLastError() << endl;
        closesocket(clientSock);
        WSACleanup();
        return 1;
    }

    // 4. 设置Tunnel地址
    sockaddr_in tunnelAddr;
    tunnelAddr.sin_family = AF_INET;

    if (InetPton(AF_INET, TUNNEL_IP, &tunnelAddr.sin_addr) != 1) {
        error << "InetPton failed." << endl;
        closesocket(clientSock);
        WSACleanup();
        return 1;
    }

    tunnelAddr.sin_port = htons(TUNNEL_PORT);

    GBNManager gbnManager(clientSock, tunnelAddr, "CLIENT");

    info << "--------------------------------------------------------" << endl;
    info << "Client (GBN Manager) is running on port " << CLIENT_LOCAL_PORT
         << endl;
    info << "Sending/Receiving via Tunnel at " << TUNNEL_IP << ":"
         << TUNNEL_PORT << endl;
    info << "--------------------------------------------------------" << endl;

    // 模拟应用层数据源 (Client -> Server)
    std::vector<std::string> messages_to_send = {
        "C_MSG_A: Ping Server!",       "C_MSG_B: Are you there?",
        "C_MSG_C: Final check.",       "C_MSG_D: Data packet four.",
        "C_MSG_E: Fifth data packet.",
    };
    int next_msg_index = 0;

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSock, &readfds);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10 * 1000;

        if (select(0, &readfds, NULL, NULL, &tv) > 0) {
            // 收到数据
            Packet received_packet;
            sockaddr_in senderAddr;
            int senderAddrLen = sizeof(senderAddr);
            int bytes = recvfrom(clientSock, (char *)&received_packet,
                                 sizeof(received_packet), 0,
                                 (SOCKADDR *)&senderAddr, &senderAddrLen);

            if (bytes > 0) {
                // 交给 GBN Manager 处理收到的包
                gbnManager.processReceivedPacket(received_packet, senderAddr);
            }
        }

        // // 从应用层获取数据并发送 (Client -> Server)
        // if (next_msg_index < messages_to_send.size()) {
        //     const std::string &msg = messages_to_send[next_msg_index];

        //     // 调用 GBN Manager 的发送方法
        //     if (gbnManager.sendData(msg.c_str(), msg.length())) {
        //         // 只有当 sendData 成功 (即窗口未满) 时，才移动到下一个消息
        //         next_msg_index++;
        //     }
        // }

        // 检查超时并重传
        gbnManager.checkTimeoutAndRetransmit();

        // 简单退出机制：所有消息都发送成功（窗口基序号追上
        // next_seq_num），则等待一段时间后退出
        if (next_msg_index >= messages_to_send.size() &&
            gbnManager.isWindowFull() == false) {
            info << "All client data sent and acknowledged. "
                 "Waiting for server traffic..." << endl;
        }
    }

    // 7. 清理
    closesocket(clientSock);
    WSACleanup();
    return 0;
}