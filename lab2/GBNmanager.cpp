#include "GBNmanager.h"
#include "../logger/logger.h"
#include <algorithm>
#include <cstdint>
#include <ostream>
#include <vector>

using logger::info;
using logger::warn;
using std::endl;

GBNManager::GBNManager(SOCKET sock, const sockaddr_in &targetAddr,
                       const std::string &roleName)
    : m_sock(sock), m_targetAddr(targetAddr), m_roleName(roleName) {
}

void GBNManager::sendAck(uint8_t ack_num, const sockaddr_in &targetAddr) {
    Packet ack_p = {};
    ack_p.type = ACK;
    ack_p.ack_num = ack_num;

    sendto(m_sock, (const char *)&ack_p, sizeof(ack_p), 0,
           (const SOCKADDR *)&targetAddr, sizeof(targetAddr));
    info << "[" << m_roleName << " RECV] Sent ACK: " << (int)ack_num << endl;
}

void GBNManager::handleAck(uint8_t ack_num) {
    uint8_t old_base = m_senderState.base;
    // 计算确认了多少个包
    uint8_t count_acked = (ack_num - m_senderState.base) % SEQ_SPACE;

    // 检查 ACK 是否有效
    if (count_acked > 0 && count_acked <= WINDOW_SIZE) {
        // base 前进到 ack_num
        m_senderState.base = ack_num;

        info << "[" << m_roleName
             << " SEND] Received valid ACK: " << (int)ack_num
             << ". Base moved from " << (int)old_base << " to "
             << (int)m_senderState.base << endl;

        if (m_senderState.base == m_senderState.next_seq_num) {
            // 窗口已空，停止定时器
            info << "[" << m_roleName << " SEND] Window empty. Timer stopped."
                 << endl;
        } else {
            // 窗口未空，重启定时器
            m_senderState.last_send_time = GetTickCount();
            info << "[" << m_roleName << " SEND] Base changed. Timer restarted."
                 << endl;
        }
    } else {
        warn << "[" << m_roleName
             << " SEND] Received duplicate or invalid ACK: " << (int)ack_num
             << ". Ignored." << endl;
    }
}

// GBN 接收端 DATA 处理
void GBNManager::handleData(const Packet &p, const sockaddr_in &senderAddr) {
    if (p.seq_num == m_receiverState.expected_seq_num) {
        // 收到期望的包
        info << "[" << m_roleName << " RECV] >>> Received "
             << "DATA" << " (Seq: " << (int)p.seq_num
             << ", Len: " << p.data_length << ")." << endl;

        if (p.type == DATA && p.data_length > 0) {
            m_receiverState.app_buffer.insert(m_receiverState.app_buffer.end(),
                                              p.data, p.data + p.data_length);
        }

        m_receiverState.expected_seq_num =
            (m_receiverState.expected_seq_num + 1) % SEQ_SPACE;

        // 发送累积 ACK
        sendAck(m_receiverState.expected_seq_num, senderAddr);
    } else {
        // 收到乱序或重复包，直接丢弃
        warn << "[" << m_roleName
             << " RECV] Received Unexpected DATA. Expected: "
             << (int)m_receiverState.expected_seq_num
             << ", Got: " << (int)p.seq_num << ". Discarding." << endl;

        sendAck(m_receiverState.expected_seq_num, senderAddr);
    }
}
bool GBNManager::isWindowFull() const {
    return (m_senderState.next_seq_num - m_senderState.base) % SEQ_SPACE >=
           WINDOW_SIZE;
}

// 发送数据
bool GBNManager::sendData(const char *buffer, int len) {
    if (isWindowFull()) {
        warn << "[" << m_roleName << " SEND] Window full. Cannot send Seq "
             << (int)m_senderState.next_seq_num << endl;
        return false;
    }

    if (len > MAX_DATA_SIZE) {
        warn << "[" << m_roleName << " SEND] Data too long. Max allowed: "
             << (int)(MAX_DATA_SIZE - 1) << endl;
        return false;
    }

    // 构造数据包
    Packet p = {};
    p.type = DATA;
    p.seq_num = m_senderState.next_seq_num;

    p.data_length = (uint16_t)len;
    memcpy(p.data, buffer, len);

    m_senderState.window[m_senderState.next_seq_num % WINDOW_SIZE] = p;

    // 发送数据
    sendto(m_sock, (const char *)&p, sizeof(p), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    info << "[" << m_roleName << " SEND] Sent DATA. Seq: " << (int)p.seq_num
         << endl;

    // 更新定时器
    if (m_senderState.base == m_senderState.next_seq_num) {
        m_senderState.last_send_time = GetTickCount();
    }

    m_senderState.next_seq_num = (m_senderState.next_seq_num + 1) % SEQ_SPACE;
    return true;
}
void GBNManager::checkTimeoutAndRetransmit() {
    if (m_senderState.base == m_senderState.next_seq_num) {
        return;
    }

    // 检查是否超时
    if (GetTickCount() - m_senderState.last_send_time >= TIMEOUT) {
        info << "\n[" << m_roleName
             << " SEND] TIMEOUT! Retransmitting from base: "
             << m_senderState.base << endl;

        uint16_t count =
            (m_senderState.next_seq_num - m_senderState.base) % SEQ_SPACE;

        // 重传所有窗口内未确认的数据包
        for (uint16_t i = 0; i < count; ++i) {
            Packet &p =
                m_senderState.window[(m_senderState.base + i) % WINDOW_SIZE];
            sendto(m_sock, (const char *)&p, sizeof(p), 0,
                   (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
            info << "[" << m_roleName
                 << " SEND] Retransmit DATA. Seq: " << (int)p.seq_num << endl;
        }

        // 重启定时器
        m_senderState.last_send_time = GetTickCount();
    }
}

// 处理收到的 Packet
void GBNManager::processReceivedPacket(const Packet &p,
                                       const sockaddr_in &senderAddr) {
    if (p.type == DATA) {
        handleData(p, senderAddr);
    } else if (p.type == ACK) {
        handleAck(p.ack_num);
    }
}

void GBNManager::resetTransaction() {
    // 重置发送状态
    m_senderState.base = 0;
    m_senderState.next_seq_num = 0;
    // 清空发送窗口缓存
    memset(m_senderState.window, 0, sizeof(m_senderState.window));
    m_senderState.last_send_time = GetTickCount(); // 重置定时器基准

    // 重置接收状态
    m_receiverState.expected_seq_num = 0;
    m_receiverState.app_buffer.clear();

    info << "[" << m_roleName << "] Transaction state reset successfully."
         << endl;
}

size_t GBNManager::read(std::vector<uint8_t> &output, size_t max_len) {
    size_t available = m_receiverState.app_buffer.size();
    size_t bytes_to_read = std::min(available, max_len);

    if (bytes_to_read == 0) {
        return 0;
    }

    // 将需要读取的字节追加到 output 中
    output.insert(output.end(), m_receiverState.app_buffer.begin(),
                  m_receiverState.app_buffer.begin() + bytes_to_read);

    // 从缓冲区中移除已读取的字节
    m_receiverState.app_buffer.erase(m_receiverState.app_buffer.begin(),
                                     m_receiverState.app_buffer.begin() +
                                         bytes_to_read);

    return bytes_to_read;
}