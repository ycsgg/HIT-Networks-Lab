#pragma once

#include "ManagerBase.h"
#include "ThreadSafeQueue.h"
#include "packet.h"

#include <atomic>
#include <mutex>
#include <thread>
#include <minwindef.h>
#include <string>
#include <vector>
#include <winsock2.h>

// 发送窗口槽结构
struct GBN_SendSlot {
    Packet pkt;
    bool used = false;
    DWORD send_time = 0;
};

class GBNManager : public ManagerBase {
  public:
    GBNManager(SOCKET sock, const sockaddr_in &targetAddr,
               const std::string &roleName);
    ~GBNManager() override;

    // ManagerBase 接口实现
    void start() override;
    void stop() override;
    bool sendData(const char *buffer, int len) override;
    size_t read(std::vector<uint8_t> &output, size_t max_len) override;

    SOCKET getSocket() const override { return m_sock; }
    std::string getRoleName() const override { return m_roleName; }
    bool isWindowFull() const override;

  protected:
    void ioThreadFunc() override;

  private:
    SOCKET m_sock;
    sockaddr_in m_targetAddr;
    std::string m_roleName;

    // 线程控制
    std::thread m_ioThread;
    std::atomic<bool> m_running{false};

    // 应用层队列（线程安全）
    ThreadSafeQueue<std::vector<uint8_t>> m_sendQueue; // 待发送数据队列
    ThreadSafeQueue<uint8_t> m_recvQueue;              // 已接收数据队列

    // 发送状态（I/O 线程访问，需要互斥保护）
    mutable std::mutex m_sendMutex;
    uint8_t m_sendBase = 0;
    uint8_t m_sendNextSeq = 0;
    GBN_SendSlot m_sendWindow[WINDOW_SIZE];
    DWORD m_lastSendTime = 0;

    // 接收状态（I/O 线程访问，需要互斥保护）
    mutable std::mutex m_recvMutex;
    uint8_t m_recvExpectedSeq = 0;
    uint8_t m_recvNextAck = 0; // 下一个要发送的累积 ACK
    bool m_ackPending = false;  // 是否有待发送的 ACK

    // 待发送的应用层数据缓冲（I/O 线程从 sendQueue 取出后暂存）
    std::vector<uint8_t> m_pendingSendData;

    // I/O 线程内部方法
    void processIncomingPackets();
    void processSendQueue();
    void checkTimeout();
    void sendPacketWithData(const char *data, int len);
    void sendAckOnly();
    void handleReceivedPacket(const Packet &p);
};
