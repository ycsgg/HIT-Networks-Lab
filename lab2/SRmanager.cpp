#include "SRmanager.h"
#include "../logger/logger.h"
#include <algorithm>

using logger::info;
using logger::warn;
using std::endl;

SRManager::SRManager(SOCKET sock, const sockaddr_in &targetAddr,
                     const std::string &roleName)
    : m_sock(sock), m_targetAddr(targetAddr), m_roleName(roleName) {
    start();
}

SRManager::~SRManager() {
    stop();
}

void SRManager::start() {
    if (m_running.exchange(true)) {
        return;
    }
    m_ioThread = std::thread(&SRManager::ioThreadFunc, this);
    info << "[" << m_roleName << "] SR I/O thread started." << endl;
}

void SRManager::stop() {
    if (!m_running.exchange(false)) {
        return;
    }
    if (m_ioThread.joinable()) {
        m_ioThread.join();
    }
    info << "[" << m_roleName << "] SR I/O thread stopped." << endl;
}

bool SRManager::sendData(const char *buffer, int len) {
    if (len <= 0 || len > MAX_DATA_SIZE) {
        return false;
    }
    
    std::vector<uint8_t> data(buffer, buffer + len);
    m_sendQueue.push(data);
    return true;
}

size_t SRManager::read(std::vector<uint8_t> &output, size_t max_len) {
    size_t count = 0;
    uint8_t byte;
    
    while (count < max_len && m_recvQueue.try_pop(byte)) {
        output.push_back(byte);
        count++;
    }
    
    return count;
}

bool SRManager::isWindowFull() const {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    return ((m_sendNextSeq - m_sendBase + SEQ_SPACE) % SEQ_SPACE) >= WINDOW_SIZE;
}

void SRManager::ioThreadFunc() {
    info << "[" << m_roleName << "] SR I/O thread running..." << endl;
    
    while (m_running) {
        processIncomingPackets();
        processSendQueue();
        checkTimeout();
        
        {
            std::lock_guard<std::mutex> lock(m_recvMutex);
            if (m_ackPending) {
                sendAckOnly();
                m_ackPending = false;
            }
        }
        
        Sleep(1);
    }
    
    info << "[" << m_roleName << "] SR I/O thread exiting..." << endl;
}

void SRManager::processIncomingPackets() {
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(m_sock, &readfds);
    
    int sel_result = select(0, &readfds, NULL, NULL, &tv);
    
    if (sel_result > 0 && FD_ISSET(m_sock, &readfds)) {
        Packet pkt;
        sockaddr_in senderAddr;
        int senderAddrLen = sizeof(senderAddr);
        
        int bytes = recvfrom(m_sock, (char *)&pkt, sizeof(pkt), 0,
                             (SOCKADDR *)&senderAddr, &senderAddrLen);
        
        if (bytes > 0) {
            handleReceivedPacket(pkt);
        }
    }
}

void SRManager::processSendQueue() {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    
    if (((m_sendNextSeq - m_sendBase + SEQ_SPACE) % SEQ_SPACE) >= WINDOW_SIZE) {
        return;
    }
    
    while (m_pendingSendData.empty()) {
        std::vector<uint8_t> data;
        if (!m_sendQueue.try_pop(data)) {
            return;
        }
        m_pendingSendData = std::move(data);
    }
    
    size_t chunk_size = std::min((size_t)MAX_DATA_SIZE, m_pendingSendData.size());
    sendPacketWithData((const char *)m_pendingSendData.data(), chunk_size);
    
    m_pendingSendData.erase(m_pendingSendData.begin(),
                           m_pendingSendData.begin() + chunk_size);
}

void SRManager::checkTimeout() {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    
    DWORD now = GetTickCount();
    
    // SR: 只重传超时且未确认的包
    for (int i = 0; i < WINDOW_SIZE; ++i) {
        if (m_sendWindow[i].used && !m_sendWindow[i].acked) {
            if (now - m_sendWindow[i].send_time >= TIMEOUT) {
                retransmitSlot(m_sendWindow[i].pkt.seq_num);
            }
        }
    }
}

void SRManager::sendPacketWithData(const char *data, int len) {
    Packet pkt = {};
    pkt.flags = FLAG_DATA;
    pkt.seq_num = m_sendNextSeq;
    pkt.data_length = (uint16_t)len;
    memcpy(pkt.data, data, len);
    
    // 捎带 ACK
    {
        std::lock_guard<std::mutex> recvLock(m_recvMutex);
        pkt.ack_num = m_recvNextAck;
        if (m_recvNextAck != 0 || m_recvExpectedSeq != 0) {
            pkt.flags |= FLAG_ACK;
            m_ackPending = false;
        }
    }
    
    // 保存到窗口
    uint8_t idx = m_sendNextSeq % WINDOW_SIZE;
    m_sendWindow[idx].pkt = pkt;
    m_sendWindow[idx].used = true;
    m_sendWindow[idx].acked = false;
    m_sendWindow[idx].send_time = GetTickCount();
    
    sendto(m_sock, (const char *)&pkt, sizeof(pkt), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    
    info << "[" << m_roleName << " SEND] Sent DATA seq:" << (int)pkt.seq_num
         << " ack:" << (int)pkt.ack_num << " len:" << len << endl;
    
    m_sendNextSeq = (m_sendNextSeq + 1) % SEQ_SPACE;
}

void SRManager::sendAckOnly() {
    Packet pkt = {};
    pkt.flags = FLAG_ACK;
    pkt.ack_num = m_recvNextAck;
    pkt.seq_num = 0;
    pkt.data_length = 0;
    
    sendto(m_sock, (const char *)&pkt, sizeof(pkt), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    
    info << "[" << m_roleName << " RECV] Sent ACK-only: " << (int)pkt.ack_num << endl;
}

void SRManager::retransmitSlot(uint8_t seq) {
    int idx = seq % WINDOW_SIZE;
    SR_SendSlot &slot = m_sendWindow[idx];
    
    if (!slot.used || slot.acked || slot.pkt.seq_num != seq) {
        return;
    }
    
    // 更新 ACK（捎带最新确认）
    {
        std::lock_guard<std::mutex> recvLock(m_recvMutex);
        slot.pkt.ack_num = m_recvNextAck;
        if (m_recvNextAck != 0 || m_recvExpectedSeq != 0) {
            slot.pkt.flags |= FLAG_ACK;
        }
    }
    
    sendto(m_sock, (const char *)&slot.pkt, sizeof(slot.pkt), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    
    slot.send_time = GetTickCount();
    
    info << "[" << m_roleName << " SEND] Retransmit seq:" << (int)seq << endl;
}

void SRManager::handleReceivedPacket(const Packet &p) {
    // 处理 ACK（SR: 单独确认每个包）
    if (p.flags & FLAG_ACK) {
        std::lock_guard<std::mutex> lock(m_sendMutex);
        
        uint8_t ack_num = p.ack_num;
        int idx = ack_num % WINDOW_SIZE;
        
        // 检查是否在窗口内
        uint8_t base_to_ack = (SEQ_SPACE + ack_num - m_sendBase) % SEQ_SPACE;
        uint8_t base_to_next = (SEQ_SPACE + m_sendNextSeq - m_sendBase) % SEQ_SPACE;
        
        if (base_to_ack < base_to_next) {
            if (m_sendWindow[idx].used && !m_sendWindow[idx].acked &&
                m_sendWindow[idx].pkt.seq_num == ack_num) {
                
                m_sendWindow[idx].acked = true;
                info << "[" << m_roleName << " SEND] Received ACK:" << (int)ack_num << endl;
                
                // 滑动窗口基准
                while (m_sendWindow[m_sendBase % WINDOW_SIZE].used &&
                       m_sendWindow[m_sendBase % WINDOW_SIZE].acked) {
                    m_sendWindow[m_sendBase % WINDOW_SIZE].used = false;
                    m_sendWindow[m_sendBase % WINDOW_SIZE].acked = false;
                    m_sendBase = (m_sendBase + 1) % SEQ_SPACE;
                }
            }
        }
    }
    
    // 处理 DATA（SR: 缓存乱序包）
    if (p.flags & FLAG_DATA) {
        std::lock_guard<std::mutex> lock(m_recvMutex);
        
        uint8_t seq = p.seq_num;
        int window_idx = seq % WINDOW_SIZE;
        
        // 检查是否在接收窗口内
        uint8_t base_to_seq = (SEQ_SPACE + seq - m_recvExpectedSeq) % SEQ_SPACE;
        
        if (base_to_seq < WINDOW_SIZE) {
            // 在窗口内，缓存数据
            if (!m_recvWindow[window_idx].received) {
                if (p.data_length > 0) {
                    m_recvWindow[window_idx].data.assign(p.data, p.data + p.data_length);
                    m_recvWindow[window_idx].len = p.data_length;
                } else {
                    m_recvWindow[window_idx].data.clear();
                    m_recvWindow[window_idx].len = 0;
                }
                m_recvWindow[window_idx].received = true;
                
                info << "[" << m_roleName << " RECV] Buffered DATA seq:"
                     << (int)seq << " len:" << p.data_length << endl;
            }
        }
        
        // 发送 ACK（SR 对每个收到的包发送 ACK）
        m_recvNextAck = seq;
        m_ackPending = true;
        
        // 将连续的已接收包交付给应用层
        while (m_recvWindow[m_recvExpectedSeq % WINDOW_SIZE].received) {
            auto &slot = m_recvWindow[m_recvExpectedSeq % WINDOW_SIZE];
            
            if (slot.len > 0) {
                for (uint8_t byte : slot.data) {
                    m_recvQueue.push(byte);
                }
            }
            
            slot.received = false;
            slot.data.clear();
            slot.len = 0;
            
            m_recvExpectedSeq = (m_recvExpectedSeq + 1) % SEQ_SPACE;
        }
    }
}
