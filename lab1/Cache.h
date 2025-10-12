#pragma once

#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>

using std::string;
using std::time_t;
using std::unordered_map;

struct CacheEntry {
    string response;       // 缓存的完整响应体
    string lastModified;   // 缓存头部：Last-Modified
    string etag;           // 缓存头部：ETag
    time_t timestamp = 0;  // 缓存存储的时间戳
    long maxAge = 0;       // 缓存最大存活时间 (来自Cache-Control)
};

class ProxyCache {
    public:
    // 获取缓存条目: 返回true表示找到，entry中为缓存数据
    // 如果过期，返回true但会删除缓存，response为空
    bool GetCacheEntry(const string &url, CacheEntry &entry);
    // 存储缓存条目
    void StoreCacheEntry(const string &url, const CacheEntry &entry);

    private:
    std::mutex cacheMutex;                          // 保护缓存Map的互斥锁
    unordered_map<string, CacheEntry> cacheMap;     // 核心缓存数据结构
};