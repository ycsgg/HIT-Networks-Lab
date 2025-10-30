#include "../logger/logger.h"
#include "GBNmanager.h"
#include "ManagerBase.h"
#include "SRmanager.h"
#include "network_utils.h"
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "ws2_32.lib")

// 定义端口和地址
#define SERVER_LOCAL_PORT 8889
#define TUNNEL_PORT       8888
#define TUNNEL_IP         "127.0.0.1"

using logger::error;
using logger::info;
using logger::warn;
using std::endl;
using std::string;
using std::vector;

void processAndRespond(ManagerBase &udpManager,
                       const std::vector<uint8_t> &data) {
    if (data.empty())
        return;

    std::string command_str(data.begin(), data.end());
    info << "[SERVER] Received Command: " << command_str << std::endl;

    // 处理控制消息：UPLOAD:filename 或 DOWNLOAD:filename 或普通命令
    if (command_str.rfind("UPLOAD:", 0) == 0) {
        std::string filename = command_str.substr(strlen("UPLOAD:"));
        // 接收文件内容
        std::vector<uint8_t> file_bytes = recvData(udpManager);
        if (file_bytes.empty()) {
            std::string err = "ERROR: Empty file received";
            sendData(udpManager, std::vector<uint8_t>(err.begin(), err.end()));
            return;
        }
        // 确保 uploads 目录存在
        std::filesystem::create_directories("uploads");
        std::string outpath = std::string("uploads/") + filename;
        std::ofstream ofs(outpath, std::ios::binary);
        if (!ofs) {
            std::string err = std::string("ERROR: Cannot create file: ") + outpath;
            sendData(udpManager, std::vector<uint8_t>(err.begin(), err.end()));
            return;
        }
        ofs.write((const char *)file_bytes.data(), file_bytes.size());
        std::string ok = std::string("UPLOAD_OK:") + filename;
        sendData(udpManager, std::vector<uint8_t>(ok.begin(), ok.end()));
        info << "Saved uploaded file to: " << outpath << std::endl;
        return;
    }

    if (command_str.rfind("DOWNLOAD:", 0) == 0) {
        std::string filename = command_str.substr(strlen("DOWNLOAD:"));
        std::string path = std::string("uploads/") + filename;
        if (!std::filesystem::exists(path)) {
            std::string err = std::string("ERROR: File not found: ") + filename;
            sendData(udpManager, std::vector<uint8_t>(err.begin(), err.end()));
            return;
        }
        // 读取文件并先发 header FILESIZE:NN
        std::ifstream ifs(path, std::ios::binary);
        std::vector<uint8_t> file_bytes((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        std::string header = std::string("FILESIZE:") + std::to_string(file_bytes.size());
        sendData(udpManager, std::vector<uint8_t>(header.begin(), header.end()));
        // 发送文件内容
        sendData(udpManager, file_bytes);
        info << "Served download for: " << filename << " (" << file_bytes.size() << " bytes)" << std::endl;
        return;
    }

    std::string response_data;
    // 确定响应内容
    if (command_str == "time_request") {
        time_t now = time(0);
        char dt[26];
        ctime_s(dt, sizeof(dt), &now);
        response_data = "time_response: " + string(dt);
    } else if (command_str == "quit") {
        response_data = "GoodBye";
    } else {
        response_data = "ERROR: Unknown command";
    }

    // 发送响应
    std::vector<uint8_t> response(response_data.begin(), response_data.end());
    sendData(udpManager, response);
    info << "[SERVER] Response sent successfully." << endl;
}

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

    // SRManager  udpManager(serverSock, tunnelAddr, "SERVER");
    GBNManager udpManager(serverSock, tunnelAddr, "SERVER");

    info << "--------------------------------------------------------" << endl;
    info << "Server (GBN/SR Manager) is running on port " << SERVER_LOCAL_PORT
         << endl;
    info << "--------------------------------------------------------" << endl;

    // Ensure uploads directory exists
    std::filesystem::create_directories("uploads");

    while (true) {
        // 接收客户端命令
        std::vector<uint8_t> data = recvData(udpManager);
        
        if (!data.empty()) {
            processAndRespond(udpManager, data);
        }

        Sleep(10); // 避免 busy-wait
    }

    closesocket(serverSock);
    WSACleanup();
    return 0;
}