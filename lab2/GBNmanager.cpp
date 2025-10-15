#include "GBNmanager.h"
#include "../logger/logger.h"
#include <algorithm>

using logger::info;
using logger::warn;
using logger::error;
using std::endl;

GBNManager::GBNManager(SOCKET sock, const sockaddr_in &targetAddr,
                       const std::string &roleName)
    : m_sock(sock), m_targetAddr(targetAddr), m_roleName(roleName) {
    start(); // 自动启动后台线程
}

GBNManager::~GBNManager() {
    stop();
}

void GBNManager::start() {
    if (m_running.exchange(true)) {
        return; // 已经在运行
    }
    m_ioThread = std::thread(&GBNManager::ioThreadFunc, this);
    info << "[" << m_roleName << "] I/O thread started." << endl;
}

void GBNManager::stop() {
    if (!m_running.exchange(false)) {
        return; // 已经停止
    }
    if (m_ioThread.joinable()) {
        m_ioThread.join();
    }
    info << "[" << m_roleName << "] I/O thread stopped." << endl;
}

bool GBNManager::sendData(const char *buffer, int len) {
    if (len <= 0 || len > MAX_DATA_SIZE) {
        return false;
    }
    
    // 将数据推入发送队列
    std::vector<uint8_t> data(buffer, buffer + len);
    m_sendQueue.push(data);
    return true;
}

size_t GBNManager::read(std::vector<uint8_t> &output, size_t max_len) {
    size_t count = 0;
    uint8_t byte;
    
    // 从接收队列中读取数据
    while (count < max_len && m_recvQueue.try_pop(byte)) {
        output.push_back(byte);
        count++;
    }
    
    return count;
}

bool GBNManager::isWindowFull() const {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    return ((m_sendNextSeq - m_sendBase + SEQ_SPACE) % SEQ_SPACE) >= WINDOW_SIZE;
}

void GBNManager::ioThreadFunc() {
    info << "[" << m_roleName << "] I/O thread running..." << endl;
    
    while (m_running) {
        // 1. 处理incoming packets
        processIncomingPackets();
        
        // 2. 处理发送队列
        processSendQueue();
        
        // 3. 检查超时
        checkTimeout();
        
        // 4. 发送pending ACK
        {
            std::lock_guard<std::mutex> lock(m_recvMutex);
            if (m_ackPending) {
                sendAckOnly();
                m_ackPending = false;
            }
        }
        
        // 短暂休眠，避免busy-wait
        Sleep(1);
    }
    
    info << "[" << m_roleName << "] I/O thread exiting..." << endl;
}

void GBNManager::processIncomingPackets() {
    // 使用非阻塞 select 检查是否有数据
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000; // 1ms
    
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

void GBNManager::processSendQueue() {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    
    // 如果窗口满了，不能发送新数据
    if (((m_sendNextSeq - m_sendBase + SEQ_SPACE) % SEQ_SPACE) >= WINDOW_SIZE) {
        return;
    }
    
    // 从待发送缓冲区或队列中获取数据
    while (m_pendingSendData.empty()) {
        std::vector<uint8_t> data;
        if (!m_sendQueue.try_pop(data)) {
            return; // 没有数据要发送
        }
        m_pendingSendData = std::move(data);
    }
    
    // 发送数据包
    size_t chunk_size = std::min((size_t)MAX_DATA_SIZE, m_pendingSendData.size());
    sendPacketWithData((const char *)m_pendingSendData.data(), chunk_size);
    
    // 移除已发送的数据
    m_pendingSendData.erase(m_pendingSendData.begin(), 
                           m_pendingSendData.begin() + chunk_size);
}

void GBNManager::checkTimeout() {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    
    // 如果窗口为空，不需要检查超时
    if (m_sendBase == m_sendNextSeq) {
        return;
    }
    
    DWORD now = GetTickCount();
    if (now - m_lastSendTime >= TIMEOUT) {
        // 超时，重传窗口内所有包
        info << "[" << m_roleName << " SEND] TIMEOUT! Retransmitting from base: "
             << (int)m_sendBase << endl;
        
        uint8_t count = (m_sendNextSeq - m_sendBase + SEQ_SPACE) % SEQ_SPACE;
        for (uint8_t i = 0; i < count; ++i) {
            uint8_t idx = (m_sendBase + i) % WINDOW_SIZE;
            if (m_sendWindow[idx].used) {
                Packet &p = m_sendWindow[idx].pkt;
                
                // 捎带最新的 ACK
                std::lock_guard<std::mutex> recvLock(m_recvMutex);
                p.ack_num = m_recvNextAck;
                if (m_recvNextAck != 0 || m_recvExpectedSeq != 0) {
                    p.flags |= FLAG_ACK;
                }
                
                sendto(m_sock, (const char *)&p, sizeof(p), 0,
                       (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
                
                info << "[" << m_roleName << " SEND] Retransmit DATA seq:"
                     << (int)p.seq_num << " ack:" << (int)p.ack_num << endl;
            }
        }
        
        m_lastSendTime = now;
    }
}

void GBNManager::sendPacketWithData(const char *data, int len) {
    // 注意：调用者已持有 m_sendMutex
    
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
            m_ackPending = false; // 已经捎带了 ACK
        }
    }
    
    // 保存到发送窗口
    uint8_t idx = m_sendNextSeq % WINDOW_SIZE;
    m_sendWindow[idx].pkt = pkt;
    m_sendWindow[idx].used = true;
    m_sendWindow[idx].send_time = GetTickCount();
    
    // 发送
    sendto(m_sock, (const char *)&pkt, sizeof(pkt), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    
    info << "[" << m_roleName << " SEND] Sent DATA seq:" << (int)pkt.seq_num
         << " ack:" << (int)pkt.ack_num << " len:" << len << endl;
    
    // 更新定时器
    if (m_sendBase == m_sendNextSeq) {
        m_lastSendTime = GetTickCount();
    }
    
    m_sendNextSeq = (m_sendNextSeq + 1) % SEQ_SPACE;
}

void GBNManager::sendAckOnly() {
    // 注意：调用者已持有 m_recvMutex
    
    Packet pkt = {};
    pkt.flags = FLAG_ACK;
    pkt.ack_num = m_recvNextAck;
    pkt.seq_num = 0; // ACK-only 包的 seq 字段不重要
    pkt.data_length = 0;
    
    sendto(m_sock, (const char *)&pkt, sizeof(pkt), 0,
           (const SOCKADDR *)&m_targetAddr, sizeof(m_targetAddr));
    
    info << "[" << m_roleName << " RECV] Sent ACK-only: " << (int)pkt.ack_num << endl;
}

void GBNManager::handleReceivedPacket(const Packet &p) {
    // 处理 ACK
    if (p.flags & FLAG_ACK) {
        std::lock_guard<std::mutex> lock(m_sendMutex);
        
        uint8_t ack_num = p.ack_num;
        uint8_t old_base = m_sendBase;
        
        // 计算确认了多少个包（GBN 累积确认）
        uint8_t count_acked = (SEQ_SPACE + ack_num - m_sendBase) % SEQ_SPACE;
        
        if (count_acked > 0 && count_acked <= WINDOW_SIZE) {
            // 滑动窗口
            m_sendBase = ack_num;
            
            info << "[" << m_roleName << " SEND] Received ACK:" << (int)ack_num
                 << ". Base moved from " << (int)old_base << " to " << (int)m_sendBase << endl;
            
            // 如果窗口变空，停止定时器
            if (m_sendBase == m_sendNextSeq) {
                info << "[" << m_roleName << " SEND] Window empty." << endl;
            } else {
                // 重启定时器
                m_lastSendTime = GetTickCount();
            }
        }
    }
    
    // 处理 DATA
    if (p.flags & FLAG_DATA) {
        std::lock_guard<std::mutex> lock(m_recvMutex);
        
        if (p.seq_num == m_recvExpectedSeq) {
            // 收到期望的包
            info << "[" << m_roleName << " RECV] Received DATA seq:"
                 << (int)p.seq_num << " len:" << p.data_length << endl;
            
            // 将数据推入接收队列
            if (p.data_length > 0) {
                for (uint16_t i = 0; i < p.data_length; ++i) {
                    m_recvQueue.push(p.data[i]);
                }
            }
            
            // 更新期望序号
            m_recvExpectedSeq = (m_recvExpectedSeq + 1) % SEQ_SPACE;
            m_recvNextAck = m_recvExpectedSeq;
            m_ackPending = true; // 标记需要发送 ACK
            
        } else {
            // 收到乱序包，丢弃（GBN 特性）
            warn << "[" << m_roleName << " RECV] Out-of-order DATA. Expected:"
                 << (int)m_recvExpectedSeq << " Got:" << (int)p.seq_num << endl;
            
            // 重新发送期望序号的 ACK
            m_ackPending = true;
        }
    }
}
