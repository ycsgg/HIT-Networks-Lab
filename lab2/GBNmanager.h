#pragma once

#include "ManagerBase.h"
#include "packet.h"

#include <iostream>
#include <minwindef.h>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>


struct SenderState {
    uint8_t base = 0;           // 发送窗口的基序号
    uint8_t next_seq_num = 0;   // 下一个要发送的序列号
    Packet window[WINDOW_SIZE]; // 发送窗口缓存
    DWORD last_send_time = 0;   // 上次发送数据包的时间
};

struct ReceiverState {
    uint8_t expected_seq_num = 0; // 期望接收的下一个序列号
    std::vector<uint8_t> app_buffer;
};

class GBNManager : public ManagerBase {
    public:
    GBNManager(SOCKET sock, const sockaddr_in &targetAddr,
               const std::string &roleName);

    // 发送端方法 (Server/Client 都可以调用此方法发送)
    bool sendData(const char *buffer, int len) override;
    void checkTimeoutAndRetransmit() override;
    void resetTransaction();

    // 接收端方法 (处理收到的 Packet)
    void processReceivedPacket(const Packet &p, const sockaddr_in &senderAddr) override;

    // 查询状态
    bool isWindowFull() const override;

    std::string getRoleName() const override { return m_roleName; }
    SOCKET getSocket() const override { return m_sock; }

    size_t read(std::vector<uint8_t> &output, size_t max_len) override;

    private:
    SOCKET m_sock;
    std::string m_roleName;
    sockaddr_in m_targetAddr;

    SenderState m_senderState;
    ReceiverState m_receiverState;

    void handleAck(uint8_t ack_num); // GBN 发送端 ACK 处理
    void handleData(const Packet &p,
                    const sockaddr_in &senderAddr); // GBN 接收端 DATA 处理
    void sendAck(uint8_t ack_num,
                 const sockaddr_in &targetAddr); // 发送 ACK 帧
};