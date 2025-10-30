#include "../logger/logger.h"
#include "GBNmanager.h"
#include "SRmanager.h"
#include "network_utils.h"
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

    // 设置Tunnel地址
    sockaddr_in tunnelAddr;
    tunnelAddr.sin_family = AF_INET;

    if (InetPton(AF_INET, TUNNEL_IP, &tunnelAddr.sin_addr) != 1) {
        error << "InetPton failed." << endl;
        closesocket(clientSock);
        WSACleanup();
        return 1;
    }

    tunnelAddr.sin_port = htons(TUNNEL_PORT);

    GBNManager udpManager(clientSock, tunnelAddr, "CLIENT");
    // SRManager  udpManager(clientSock, tunnelAddr, "CLIENT");

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