#include "HttpClient.h"
#include "Cache.h"
#include "ProxyPolicy.h"
#include <algorithm>
#include <iostream>
#include <string>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

constexpr int DEFAULT_HTTP_PORT = 80;
using std::cerr;
using std::endl;

ProxyCache g_cache; // 全局缓存实例

// 辅助函数：发送响应给客户端
void SendResponse(SOCKET sock, const string &response) {
    send(sock, response.c_str(), response.length(), 0);
}

// 辅助函数：发送 403 Forbidden 响应
void SendForbidden(SOCKET sock);

// 辅助函数：发送 302 Redirect 响应
void SendRedirect(SOCKET sock, const std::string &targetUrl);

// 接收目标服务器的完整响应
string HttpClient::RecvFullResponse(SOCKET targetSocket) {
    // 循环接收数据直到连接关闭
    // ... (接收逻辑，已在文件开头实现)
    string response;
    char buffer[4096];
    int bytesRecv;
    do {
        bytesRecv = recv(targetSocket, buffer, sizeof(buffer), 0);
        if (bytesRecv > 0) {
            response.append(buffer, bytesRecv);
        } else if (bytesRecv < 0) {
            return "";
        }
    } while (bytesRecv > 0);

    return response;
}

// 在请求中添加头部 (用于添加条件请求头)
string HttpClient::AddHeader(const string &request, const string &key,
                             const string &value) {
    // ... (头部添加逻辑，已在文件开头实现)
    size_t bodyStart = request.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        // 在请求头和请求体之间插入新头部
        return request.substr(0, bodyStart + 2) + key + ": " + value + "\r\n" +
               request.substr(bodyStart + 2);
    }
    return request;
}

// 从目标服务器响应中提取缓存相关头部
CacheEntry HttpClient::ExtractCacheHeaders(const string &response) {
    CacheEntry entry;

    // 1. Last-Modified
    // ... (提取 Last-Modified 逻辑，已在文件开头实现)
    size_t pos = response.find("\r\nLast-Modified:");
    if (pos != std::string::npos) {
        size_t start = pos + 17;
        size_t end = response.find("\r\n", start);
        if (end != std::string::npos) {
            entry.lastModified = response.substr(start, end - start);
        }
    }

    // 2. ETag
    // ... (提取 ETag 逻辑，已在文件开头实现)
    pos = response.find("\r\nETag:");
    if (pos != std::string::npos) {
        size_t start = pos + 8; 
        size_t end = response.find("\r\n", start);
        if (end != std::string::npos) {
            entry.etag = response.substr(start, end - start);
        }
    }

    // 3. Cache-Control (Max-Age)
    // ... (提取 Max-Age 逻辑，已在文件开头实现)
    pos = response.find("max-age=");
    if (pos != std::string::npos) {
        // 简单处理 max-age=后紧跟数字的情况
        entry.maxAge = stol(response.substr(pos + 8)); 
    }

    return entry;
}

// 处理客户端请求的核心逻辑
void HttpClient::Run() {

    // 1. 接收客户端请求 (直到收到完整报文头)
    // ... (接收请求逻辑，已在文件开头实现)
    char buffer[4096];
    int bytesRecv;

    do {
        bytesRecv = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesRecv > 0) {
            buffer[bytesRecv] = '\0';
            clientRequest.append(buffer, bytesRecv);
        }
    } while (bytesRecv > 0 &&
             clientRequest.find("\r\n\r\n") == std::string::npos);
    if (bytesRecv <= 0) {
        cerr << "Failed to receive client request." << endl;
        return;
    }


    string host;
    int port;
    string modifiedRequest;
    string fullUrl;

    // 2. 解析请求
    if (!ParseRequest(host, port, modifiedRequest, fullUrl)) {
        cerr << "Failed to parse client request." << endl;
        return;
    }

    string normalizedHost = ProxyPolicy::formatHost(host);

    // 3. 策略检查 - 用户访问权限
    if (g_policy.isUserAllowed(clientIP) == false) {
        std::cout << "Access Denied: User " << clientIP << " not allowed."
                  << std::endl;
        SendForbidden(clientSocket);
        return;
    }

    // 4. 策略检查 - 网站黑名单
    if (g_policy.isWebsiteBlocked(normalizedHost)) {
        std::cout << "Access Denied: Website " << normalizedHost
                  << " is blocked." << std::endl;
        SendForbidden(clientSocket);
        return;
    }

    // 5. 策略检查 - 网站引导/钓鱼规则 (重定向)
    if (g_policy.getPhishingRedirect(normalizedHost, host)) {
        std::cout << "Redirecting " << normalizedHost << " to " << host
                  << std::endl;
        SendRedirect(clientSocket, host);
        return;
    }

    // 6. 缓存检查
    CacheEntry cacheEntry;
    bool cacheExists = g_cache.GetCacheEntry(fullUrl, cacheEntry);
    bool isFresh = false;

    if (cacheExists) {
        time_t currentTime = time(nullptr);
        // 缓存判断逻辑：检查 maxAge 是否过期
        if (currentTime - cacheEntry.timestamp <= cacheEntry.maxAge) {
            isFresh = true; // 缓存新鲜 (Fresh Hit)
        } else {
            // 缓存过期 (Stale Hit): 准备条件请求
            if (!cacheEntry.lastModified.empty()) {
                modifiedRequest =
                    AddHeader(modifiedRequest, "If-Modified-Since",
                              cacheEntry.lastModified);
            } else if (!cacheEntry.etag.empty()) {
                modifiedRequest = AddHeader(modifiedRequest, "If-None-Match",
                                            cacheEntry.etag);
            }
        }
    }

    // 7. 处理 Fresh Hit
    if (isFresh) {
        if (send(clientSocket, cacheEntry.response.c_str(),
                 cacheEntry.response.size(), 0) == SOCKET_ERROR) {
            cerr << "Failed to send cached response to client."
                 << WSAGetLastError() << endl;
        }
        std::cout << "Cache Hit: Fresh cache for " << fullUrl << endl;
        return;
    }

    // 8. 连接目标服务器
    if (!ConnectTargetServer(host, port)) {
        cerr << "Failed to connect to target server : " << host << ":" << port
             << endl;
        return;
    }

    // 9. 发送请求 (可能是条件请求)
    if (send(targetSocket, modifiedRequest.c_str(), modifiedRequest.size(),
             0) == SOCKET_ERROR) {
        cerr << "Failed to send request to target server." << WSAGetLastError()
             << endl;
    }

    // 10. 接收目标服务器响应
    string fullResponse = RecvFullResponse(targetSocket);

    if (fullResponse.empty()) {
        cerr << "Failed to receive response from target server." << endl;
        return;
    }

    // 11. 响应处理 - 304 Not Modified
    else if (fullResponse.find("HTTP/1.1 304") != std::string::npos) {
        std::cout << "Cache Hit: 304 Not Modified for " << fullUrl << std::endl;

        // 转发缓存内容给客户端
        if (send(clientSocket, cacheEntry.response.c_str(),
                 cacheEntry.response.size(), 0) == SOCKET_ERROR) {
            std::cerr << "Failed to send 304 cached content." << std::endl;
        }

        // **更新缓存时间戳 (Stale -> Fresh)**
        cacheEntry.timestamp = time(nullptr);
        g_cache.StoreCacheEntry(fullUrl, cacheEntry);
    }

    // 12. 响应处理 - 200 OK
    else if (fullResponse.find("HTTP/1.1 200") != std::string::npos) {
        std::cout << "Cache Miss: 200 OK for " << fullUrl << std::endl;

        // 提取缓存相关头部
        CacheEntry newEntry = ExtractCacheHeaders(fullResponse);
        newEntry.response = fullResponse;

        // 存储到缓存 (会自动设置新的 timestamp)
        g_cache.StoreCacheEntry(fullUrl, newEntry);

        // 转发响应给客户端
        if (send(clientSocket, fullResponse.c_str(), fullResponse.size(), 0) ==
            SOCKET_ERROR) {
            std::cerr << "Failed to send 200 response to client." << std::endl;
        }
    } 
    // 13. 响应处理 - 其他状态码 (如 4xx, 5xx)
    else {
        if (send(clientSocket, fullResponse.c_str(), fullResponse.size(), 0) ==
            SOCKET_ERROR) {
            std::cerr << "Failed to send other response to client."
                      << std::endl;
        }
    }

    // 14. 转发剩余数据 (用于处理Keep-Alive或剩余响应体)
    RelayData();
}

// 解析客户端的代理请求
bool HttpClient::ParseRequest(string &host, int &port, string &modifiedRequest,
                              string &fullUrl) {
    // ... (请求解析逻辑，已在文件末尾实现)
    std::stringstream ss(clientRequest);
    string line;
    getline(ss, line);

    // 查找请求行中的 URL (例如 GET http://host:port/path HTTP/1.1)
    size_t start = line.find(' ') + 1;
    size_t end = line.find(' ', start);
    if (start == string::npos || end == string::npos)
        return false;

    fullUrl = line.substr(start, end - start);

    // 提取 Host 和 Port
    size_t hostStart = fullUrl.find("://");
    if (hostStart == string::npos) return false;
    hostStart += 3; 

    size_t pathStart = fullUrl.find('/', hostStart);
    string hostPort = (pathStart == string::npos)
                          ? fullUrl.substr(hostStart)
                          : fullUrl.substr(hostStart, pathStart - hostStart);

    size_t colon = hostPort.find(':');
    if (colon != string::npos) {
        host = hostPort.substr(0, colon);
        port = stoi(hostPort.substr(colon + 1));
    } else {
        host = hostPort;
        port = DEFAULT_HTTP_PORT;
    }

    // 构造针对目标服务器的请求行 (将完整URL替换为相对路径)
    string path = (pathStart == string::npos) ? "/" : fullUrl.substr(pathStart);
    string newRequestLine = line.substr(0, start) + path + line.substr(end);

    // 重新组合请求报文 (只替换请求行)
    modifiedRequest = newRequestLine + "\n" +
                      clientRequest.substr(clientRequest.find('\n') + 1);

    // 确保整个报文使用 CRLF
    // ... (CRLF 转换逻辑，已在文件末尾实现)
    size_t crlf_pos = modifiedRequest.find('\n');
    if (crlf_pos != string::npos) {
        modifiedRequest.replace(crlf_pos, 1, "\r\n");
    }

    replace(modifiedRequest.begin(), modifiedRequest.end(), '\n', '\r');
    replace(modifiedRequest.begin(), modifiedRequest.end(), '\r', '\n');


    return true;
}

// 连接目标 Web 服务器
bool HttpClient::ConnectTargetServer(const std::string &host, int port) {
    // ... (连接逻辑，已在文件末尾实现)
    addrinfo hints = {}, *res;
    // ... (getaddrinfo 和 socket/connect 逻辑)
    string portStr = std::to_string(port);

    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        return false;
    }

    targetSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (connect(targetSocket, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR) {
        closesocket(targetSocket);
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);
    return true;
}

// 转发剩余数据 (用于Keep-Alive)
void HttpClient::RelayData() {
    // ... (数据转发逻辑，已在文件末尾实现)
    char buffer[4096];
    int bytesRecv;
    do {
        bytesRecv = recv(targetSocket, buffer, sizeof(buffer), 0);
        if (bytesRecv > 0) {
            if (send(clientSocket, buffer, bytesRecv, 0) == SOCKET_ERROR) {
                break;
            }
        } else if (bytesRecv < 0) {
            std::cerr << "Recv from target error: " << WSAGetLastError()
                      << std::endl;
        }
    } while (bytesRecv > 0);
}

// 发送 403 Forbidden 响应
void SendForbidden(SOCKET sock) {
    std::string body = "<html><body><h1>403 Forbidden</h1><p>Access blocked by "
                       "proxy policy.</p></body></html>";
    std::stringstream response;
    response << "HTTP/1.1 403 Forbidden\r\n";
    response << "Content-Type: text/html; charset=utf-8\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n\r\n";

    std::string fullResponse = response.str() + body;

    SendResponse(sock, fullResponse);
}

// 发送 302 Redirect 响应
void SendRedirect(SOCKET sock, const std::string &targetUrl) {
    std::string response = "HTTP/1.1 302 Found\r\n"
                           "Location: " +
                           targetUrl +
                           "\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
    SendResponse(sock, response);
}