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

// 发送窗口槽结构（SR需要单独跟踪每个包的ACK状态）
struct SR_SendSlot {
    Packet pkt;
    bool used = false;
    bool acked = false;
    DWORD send_time = 0;
};

// 接收窗口槽结构（SR需要缓存乱序包）
struct SR_RecvSlot {
    std::vector<uint8_t> data;
    bool received = false;
    uint16_t len = 0;
};

class SRManager : public ManagerBase {
  public:
    SRManager(SOCKET sock, const sockaddr_in &targetAddr,
              const std::string &roleName);
    ~SRManager() override;

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
    ThreadSafeQueue<std::vector<uint8_t>> m_sendQueue;
    ThreadSafeQueue<uint8_t> m_recvQueue;

    // 发送状态
    mutable std::mutex m_sendMutex;
    uint8_t m_sendBase = 0;
    uint8_t m_sendNextSeq = 0;
    SR_SendSlot m_sendWindow[WINDOW_SIZE];

    // 接收状态
    mutable std::mutex m_recvMutex;
    uint8_t m_recvExpectedSeq = 0;
    uint8_t m_recvNextAck = 0;
    SR_RecvSlot m_recvWindow[WINDOW_SIZE];
    bool m_ackPending = false;

    // 待发送数据缓冲
    std::vector<uint8_t> m_pendingSendData;

    // I/O 线程方法
    void processIncomingPackets();
    void processSendQueue();
    void checkTimeout();
    void sendPacketWithData(const char *data, int len);
    void sendAckOnly();
    void handleReceivedPacket(const Packet &p);
    void retransmitSlot(uint8_t seq);
};
