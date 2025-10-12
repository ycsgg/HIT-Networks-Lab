#pragma once

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>

class ProxyPolicy {
    public:
    // 1. 网站过滤列表 (Blacklist): 存储格式化后的Host (小写, 无端口)
    std::unordered_set<std::string> blockedWebsites;

    // 2. 用户过滤列表: 允许访问的客户端IP列表 (Whitelist)
    std::unordered_set<std::string> allowedUsers; 

    // 3. 网站引导/钓鱼规则: 键=原始Host(格式化后), 值=引导目标URL
    std::unordered_map<std::string, std::string> phishingRules;

    // 格式化Host: 转小写并去除端口号
    static std::string formatHost(const std::string &host) {
        std::string lowerHost = host;
        std::transform(lowerHost.begin(), lowerHost.end(), lowerHost.begin(),
                       ::tolower); // 转换为小写
        size_t colonPos = lowerHost.find(':');
        if (colonPos != std::string::npos) {
            lowerHost.erase(colonPos); // 去除端口
        }
        return lowerHost;
    }

    // 检查用户是否允许访问 (空列表表示允许所有用户)
    bool isUserAllowed(const std::string &clientIP) const {
        return allowedUsers.empty() ||
               allowedUsers.count(clientIP) > 0; 
    }

    // 检查网站是否被阻止
    bool isWebsiteBlocked(const std::string &host) const {
        std::string formattedHost = formatHost(host);
        return blockedWebsites.count(formattedHost) > 0;
    }

    // 获取重定向目标URL
    bool getPhishingRedirect(const std::string &host,
                             std::string &targetUrl) const {
        std::string formattedHost = formatHost(host);
        auto it = phishingRules.find(formattedHost);
        if (it != phishingRules.end()) {
            targetUrl = it->second;
            return true;
        }
        return false;
    }

    // 添加被阻止的网站
    void addBlockedWebsite(const std::string &host) {
        blockedWebsites.insert(formatHost(host));
    }
    // 添加允许访问的用户
    void addAllowedUser(const std::string &clientIP) {
        allowedUsers.insert(clientIP);
    }
    // 添加钓鱼规则
    void addPhishingRule(const std::string &host,
                         const std::string &targetUrl) {
        phishingRules[formatHost(host)] = targetUrl;
    }
};

extern ProxyPolicy g_policy; // 全局策略实例