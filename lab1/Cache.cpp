#include "Cache.h"

using std::lock_guard;
using std::mutex;

constexpr int MAX_CACHE_AGE = 60; // 1 minute

bool ProxyCache::GetCacheEntry(const string &url, CacheEntry &entry) {
    lock_guard<mutex> lock(cacheMutex);
    auto it = cacheMap.find(url);
    if (it != cacheMap.end()) {
        time_t currentTime = time(nullptr);
        entry = it->second;
        long expiryTime =
            it->second.maxAge > 0 ? it->second.maxAge : MAX_CACHE_AGE;
        if (difftime(currentTime, it->second.timestamp) <= expiryTime) {
            return !entry.response.empty();
        } else {
            cacheMap.erase(it);
            return true;
        }
    }
    return false;
}
void ProxyCache::StoreCacheEntry(const string &url, const CacheEntry &entry) {
    lock_guard<mutex> lock(cacheMutex);
    CacheEntry newEntry = entry;
    newEntry.timestamp = time(nullptr);
    cacheMap[url] = newEntry;
}