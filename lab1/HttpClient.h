#pragma once

#include "Cache.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

using std::string;

class HttpClient {
    public:
    HttpClient(SOCKET clientSocket, const sockaddr_in *clientAddr)
        : clientSocket(clientSocket) {
        char ipBuffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr->sin_addr), ipBuffer, INET_ADDRSTRLEN);
        clientIP = ipBuffer;
    }
    ~HttpClient() {
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
        }
        if (targetSocket != INVALID_SOCKET) {
            closesocket(targetSocket);
        }
    }
    void Run();

    private:
    SOCKET clientSocket = INVALID_SOCKET;
    SOCKET targetSocket = INVALID_SOCKET;
    string clientIP;
    string clientRequest;

    bool ParseRequest(std::string &host, int &port,
                      std::string &modifiedRequest, std::string &fullUrl);
    std::string RecvFullResponse(SOCKET targetSocket);
    CacheEntry ExtractCacheHeaders(const std::string &response);
    std::string AddHeader(const std::string &request, const std::string &key,
                          const std::string &value);
    bool ConnectTargetServer(const std::string &host, int port);
    void RelayData();
};