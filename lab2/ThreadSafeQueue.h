#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>
#include <vector>

// 线程安全队列，用于主线程和 I/O 线程之间传递数据
template <typename T> class ThreadSafeQueue {
  public:
    ThreadSafeQueue() = default;

    // 推送数据到队列
    void push(const T &item) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(item);
        m_cv.notify_one();
    }

    // 尝试弹出数据（非阻塞）
    bool try_pop(T &item) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.empty()) {
            return false;
        }
        item = m_queue.front();
        m_queue.pop();
        return true;
    }

    // 阻塞等待并弹出数据（带超时）
    bool wait_pop(T &item, int timeout_ms) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [this] { return !m_queue.empty(); })) {
            item = m_queue.front();
            m_queue.pop();
            return true;
        }
        return false;
    }

    // 检查队列是否为空
    bool empty() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

    // 获取队列大小
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

  private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::queue<T> m_queue;
};

// 用于待发送数据块的结构
struct SendDataBlock {
    std::vector<uint8_t> data;
};

// 用于已接收数据块的结构（与 SendDataBlock 相同，但语义不同）
using RecvDataBlock = std::vector<uint8_t>;
