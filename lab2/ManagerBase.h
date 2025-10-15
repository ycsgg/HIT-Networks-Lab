#pragma once

#include "ThreadSafeQueue.h"
#include "packet.h"
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <winsock2.h>

class ManagerBase {
  public:
    virtual ~ManagerBase() = default;

    // 启动后台 I/O 线程
    virtual void start() = 0;

    // 停止后台 I/O 线程
    virtual void stop() = 0;

    // 应用层接口：发送数据（推送到发送队列，非阻塞）
    // 返回 true 表示成功加入队列，false 表示队列满或其他错误
    virtual bool sendData(const char *buffer, int len) = 0;

    // 应用层接口：读取接收到的数据（从接收队列读取）
    // 返回实际读取的字节数
    virtual size_t read(std::vector<uint8_t> &output, size_t max_len) = 0;

    // 查询接口
    virtual SOCKET getSocket() const = 0;
    virtual std::string getRoleName() const = 0;
    virtual bool isWindowFull() const = 0;

  protected:
    // 后台线程入口函数（由子类实现具体的 I/O 逻辑）
    virtual void ioThreadFunc() = 0;
};
