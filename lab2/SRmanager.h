#pragma once

#include "ManagerBase.h"
#include "packet.h"
#include <minwindef.h>
#include <string>
#include <vector>
#include <winsock2.h>

struct SR_SenderSlot {
    Packet pkt;
    bool used = false;
    bool acked = false;
    DWORD send_time = 0;
};

struct SR_RecvSlot {
    std::vector<uint8_t> data;
    bool received = false;
    uint16_t len = 0;
};

class SRManager : public ManagerBase {
    public:
    SRManager(SOCKET sock, const sockaddr_in &targetAddr,
              const std::string &roleName);
    ~SRManager() override = default;

    // ManagerBase overrides
    SOCKET getSocket() const override;
    std::string getRoleName() const override;
    void processReceivedPacket(const Packet &p,
                               const sockaddr_in &senderAddr) override;
    void checkTimeoutAndRetransmit() override;
    bool sendData(const char *buffer, int len) override;
    bool isWindowFull() const override;
    size_t read(std::vector<uint8_t> &output, size_t max_len) override;

    private:
    SOCKET m_sock;
    sockaddr_in m_targetAddr;
    std::string m_roleName;

    // Sender state
    uint8_t base = 0;
    uint8_t next_seq = 0;
    SR_SenderSlot window[WINDOW_SIZE];

    // Receiver state
    uint8_t expected_seq = 0;
    std::vector<uint8_t> app_buffer;

    SR_RecvSlot recv_window[WINDOW_SIZE];

    void sendAck(uint8_t ack_num, const sockaddr_in &targetAddr);
    void retransmitSlot(uint8_t seq);
};
