#include "../logger/logger.h"
#include "GBNmanager.h"
#include "SRmanager.h"
#include "network_utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// 定义端口和地址
#define CLIENT_LOCAL_PORT 8887
#define TUNNEL_PORT       8888
#define TUNNEL_IP         "127.0.0.1"

using logger::error;
using logger::info;
using logger::warn;
using std::endl;
using std::string;
using std::vector;

void processResponse(const std::vector<uint8_t> &data) {
    if (data.empty())
        return;
    string data_str(data.begin(), data.end());
    info << "[CLIENT] Received response: " << data_str << endl;
}
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

    // GBNManager udpManager(clientSock, tunnelAddr, "CLIENT");
    SRManager  udpManager(clientSock, tunnelAddr, "CLIENT");

    info << "--------------------------------------------------------" << endl;
    info << "Client (GBN/SR Manager) is running on port " << CLIENT_LOCAL_PORT
         << endl;
    info << "Sending/Receiving via Tunnel at " << TUNNEL_IP << ":"
         << TUNNEL_PORT << endl;
    info << "--------------------------------------------------------" << endl;

    while (true) {
        info << "Command >> ";
        info.flush();
        std::string line;
        if (!std::getline(std::cin, line))
            break;
        if (line.empty())
            continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;


        if (cmd == "time") {
            std::string command_data = "time_request";
            sendData(udpManager, std::vector<uint8_t>(command_data.begin(),
                                                      command_data.end()));
            std::vector<uint8_t> response = recvData(udpManager);
            processResponse(response);
            continue;
        }

        if (cmd == "quit") {
            std::string command_data = "quit";
            sendData(udpManager, std::vector<uint8_t>(command_data.begin(),
                                                      command_data.end()));
            std::vector<uint8_t> response = recvData(udpManager);
            processResponse(response);
            info << "Quit command processed. Exiting." << std::endl;
            break;
        }

        if (cmd == "echo") {
            // Echo 命令：发送文本，服务器原样返回（测试全双工）
            std::string message;
            std::getline(iss, message);
            if (message.empty()) {
                warn << "Usage: echo <message>" << endl;
                continue;
            }
            message = message.substr(1); // 去掉前导空格
            
            std::string command_data = "ECHO:" + message;
            info << "[CLIENT] Sending echo request: " << message << endl;
            sendData(udpManager, std::vector<uint8_t>(command_data.begin(),
                                                      command_data.end()));
            std::vector<uint8_t> response = recvData(udpManager);
            processResponse(response);
            continue;
        }

        if (cmd == "ping") {
            // Ping 命令：发送多个连续请求，测试全双工并发（观察 seq/ack）
            int count = 5;
            iss >> count;
            if (count <= 0 || count > 100) count = 5;
            
            info << "[CLIENT] Sending " << count << " ping requests..." << endl;
            
            for (int i = 0; i < count; ++i) {
                std::string command_data = "PING:" + std::to_string(i);
                sendData(udpManager, std::vector<uint8_t>(command_data.begin(),
                                                          command_data.end()));
                info << "[CLIENT] Ping " << i << " sent" << endl;
                Sleep(100); // 短暂间隔观察全双工效果
            }
            
            // 接收所有响应
            for (int i = 0; i < count; ++i) {
                std::vector<uint8_t> response = recvData(udpManager);
                processResponse(response);
            }
            continue;
        }

        if (cmd == "stream") {
            // Stream 命令：持续发送数据流，测试全双工持续传输
            int duration_sec = 3;
            iss >> duration_sec;
            if (duration_sec <= 0 || duration_sec > 60) duration_sec = 3;
            
            info << "[CLIENT] Streaming for " << duration_sec << " seconds..." << endl;
            
            DWORD start_time = GetTickCount();
            int packet_count = 0;
            
            while ((GetTickCount() - start_time) < (DWORD)(duration_sec * 1000)) {
                std::string command_data = "STREAM:" + std::to_string(packet_count++);
                sendData(udpManager, std::vector<uint8_t>(command_data.begin(),
                                                          command_data.end()));
                Sleep(50); // 每 50ms 发送一个包
            }
            
            info << "[CLIENT] Sent " << packet_count << " stream packets" << endl;
            
            // 接收所有响应
            for (int i = 0; i < packet_count; ++i) {
                std::vector<uint8_t> response = recvData(udpManager);
                if (i == 0 || i == packet_count - 1) {
                    // 只显示第一个和最后一个响应
                    processResponse(response);
                }
            }
            info << "[CLIENT] Received all " << packet_count << " responses" << endl;
            continue;
        }

        if (cmd == "upload") {
            std::string localpath, remotename;
            iss >> localpath >> remotename;
            if (localpath.empty()) {
                warn << "Usage: upload <localpath> [remotename]" << endl;
                continue;
            }
            if (remotename.empty()) {
                remotename =
                    std::filesystem::path(localpath).filename().string();
            }

            // 读取本地文件
            std::ifstream ifs(localpath, std::ios::binary);
            if (!ifs) {
                error << "Failed to open local file: " << localpath << endl;
                continue;
            }
            std::vector<uint8_t> file_bytes(
                (std::istreambuf_iterator<char>(ifs)),
                std::istreambuf_iterator<char>());

            // 发送控制消息
            std::string ctrl = std::string("UPLOAD:") + remotename;
            sendData(udpManager,
                     std::vector<uint8_t>(ctrl.begin(), ctrl.end()));

            // 发送文件内容
            sendData(udpManager, file_bytes);

            // 等待服务器确认
            std::vector<uint8_t> response = recvData(udpManager);
            processResponse(response);
            continue;
        }

        if (cmd == "download") {
            std::string remotename, localname;
            iss >> remotename >> localname;
            if (remotename.empty() || localname.empty()) {
                warn << "Usage: download <remotename> <localname>" << endl;
                continue;
            }

            // 发送下载请求
            std::string ctrl = std::string("DOWNLOAD:") + remotename;
            sendData(udpManager,
                     std::vector<uint8_t>(ctrl.begin(), ctrl.end()));

            // 先接收控制响应（可能是 ERROR 或 FILESIZE）
            std::vector<uint8_t> header = recvData(udpManager);
            if (header.empty()) {
                error << "Empty response for download request" << endl;
                continue;
            }
            std::string header_str(header.begin(), header.end());
            if (header_str.rfind("ERROR:", 0) == 0) {
                info << "Server error: " << header_str << endl;
                continue;
            }
            if (header_str.rfind("FILESIZE:", 0) == 0) {
                // 接收文件数据
                std::vector<uint8_t> file_bytes = recvData(udpManager);
                if (file_bytes.empty()) {
                    error << "Failed to receive file bytes" << endl;
                    continue;
                }
                // 写入本地文件
                std::ofstream ofs(localname, std::ios::binary);
                if (!ofs) {
                    error << "Failed to create local file: " << localname
                          << endl;
                    continue;
                }
                ofs.write((const char *)file_bytes.data(), file_bytes.size());
                info << "Downloaded " << remotename << " -> " << localname
                     << endl;
                continue;
            }

            warn << "Unexpected response header: " << header_str << endl;
            continue;
        }

        warn << "Unknown command: " << cmd << endl;
    }
    // 7. 清理
    closesocket(clientSock);
    WSACleanup();
    return 0;
}