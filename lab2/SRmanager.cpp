#include "SRmanager.h"
#include "../logger/logger.h"
#include <cstring>

using logger::info;
using logger::warn;

SRManager::SRManager(SOCKET sock, const sockaddr_in &targetAddr,
                     const std::string &roleName)
    : m_sock(sock), m_targetAddr(targetAddr), m_roleName(roleName) {
}

SOCKET SRManager::getSocket() const {
    return m_sock;
}
std::string SRManager::getRoleName() const {
    return m_roleName;
}

void SRManager::sendAck(uint8_t ack_num, const sockaddr_in &targetAddr) {
    Packet ack_p = {};
    ack_p.type = ACK;
    ack_p.ack_num = ack_num;
    sendto(m_sock, (const char *)&ack_p, sizeof(ack_p), 0,
           (const SOCKADDR *)&targetAddr, sizeof(targetAddr));
    info << "[" << m_roleName << " RECV] Sent ACK: " << (int)ack_num
         << std::endl;
}

bool SRManager::isWindowFull() const {
    return ((next_seq - base + SEQ_SPACE) % SEQ_SPACE) >= WINDOW_SIZE;
}

bool SRManager::sendData(const char *buffer, int len) {
    if (len > MAX_DATA_SIZE) {
        warn << "[" << m_roleName << " SEND] Data too long" << std::endl;
        return false;
    }

    if (isWindowFull())
        return false;

    // place in next_seq slot
    uint8_t seq = next_seq;
    SR_SenderSlot &slot = window[seq % WINDOW_SIZE];
    Packet p = {};
    p.type = DATA;
    p.seq_num = seq;
    p.data_length = (uint16_t)len;
    memcpy(p.data, buffer, len);
    slot.pkt = p;
    slot.used = true;
    slot.acked = false;
    slot.send_time = GetTickCount();

    sendto(m_sock, (const char *)&p, sizeof(p), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    info << "[" << m_roleName << " SEND] Sent DATA Seq:" << (int)seq
         << std::endl;

    next_seq = (next_seq + 1) % SEQ_SPACE;
    return true;
}

void SRManager::retransmitSlot(uint8_t seq) {
    // 使用 seq % WINDOW_SIZE 找到正确的索引
    int idx = seq % WINDOW_SIZE;
    SR_SenderSlot &slot = window[idx];
    
    if (!slot.used || slot.acked || slot.pkt.seq_num != seq) return;
    
    sendto(m_sock, (const char *)&slot.pkt, sizeof(slot.pkt), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    slot.send_time = GetTickCount();
    info << "[" << m_roleName << " SEND] Retransmit Seq:" << (int)seq << std::endl;
}

void SRManager::checkTimeoutAndRetransmit() {
    DWORD now = GetTickCount();
    for (int i = 0; i < WINDOW_SIZE; ++i) {
        if (window[i].used && !window[i].acked) {
            if (now - window[i].send_time >= TIMEOUT) {
                retransmitSlot(window[i].pkt.seq_num);
            }
        }
    }
}

void SRManager::processReceivedPacket(const Packet &p,
                                      const sockaddr_in &senderAddr) {
    if (p.type == ACK) {
        uint8_t ack = p.ack_num;
        int base_to_ack_dist = (SEQ_SPACE + ack - base) % SEQ_SPACE;
        int base_to_next_dist = (SEQ_SPACE + next_seq - base) % SEQ_SPACE;
        int idx = ack % WINDOW_SIZE;
        if (base_to_ack_dist < base_to_next_dist) {
            if (window[idx].used && !window[idx].acked &&
                window[idx].pkt.seq_num == ack) {
                window[idx].acked = true;
                info << "[" << m_roleName << " SEND] Received ACK " << (int)ack
                     << std::endl;
                while (window[base % WINDOW_SIZE].used &&
                       window[base % WINDOW_SIZE].acked) {
                    window[base % WINDOW_SIZE].used = false;
                    window[base % WINDOW_SIZE].acked = false;
                    base = (base + 1) % SEQ_SPACE;
                }
            }
        }
    } else if (p.type == DATA) {
        uint8_t seq = p.seq_num;
        int window_idx = seq % WINDOW_SIZE;

        int base_to_seq_dist = (SEQ_SPACE + seq - expected_seq) % SEQ_SPACE;

        if (base_to_seq_dist < WINDOW_SIZE) {

            // Store packet in receive buffer if within window
            if (!recv_window[window_idx].received) {
                if (p.data_length > 0) {
                    recv_window[window_idx].data.assign(p.data,
                                                        p.data + p.data_length);
                    recv_window[window_idx].len = p.data_length;
                } else {
                    recv_window[window_idx].data.clear();
                    recv_window[window_idx].len = 0;
                }
                recv_window[window_idx].received = true;
            }
        }

        // Send ACK for the received seq (SR ACK is per-packet)
        sendAck(seq, senderAddr);

        // Deliver contiguous in-order packets to application buffer
        while (recv_window[expected_seq % WINDOW_SIZE].received) {
            auto &slot = recv_window[expected_seq % WINDOW_SIZE];
            if (slot.len > 0) {
                app_buffer.insert(app_buffer.end(), slot.data.begin(),
                                  slot.data.end());
            }
            slot.received = false;
            slot.data.clear();
            slot.len = 0;
            expected_seq = (expected_seq + 1) % SEQ_SPACE;
        }
    }
}

size_t SRManager::read(std::vector<uint8_t> &output, size_t max_len) {
    size_t available = app_buffer.size();
    size_t bytes_to_read = std::min(available, max_len);
    if (bytes_to_read == 0)
        return 0;
    output.insert(output.end(), app_buffer.begin(),
                  app_buffer.begin() + bytes_to_read);
    app_buffer.erase(app_buffer.begin(), app_buffer.begin() + bytes_to_read);
    return bytes_to_read;
}
