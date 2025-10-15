#include "network_utils.h"

void _processNetworkIO(ManagerBase &udpManager, DWORD waitTimeMs = 10) {
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = waitTimeMs * 1000;

    fd_set readfds;
    FD_ZERO(&readfds);

    SOCKET sock = udpManager.getSocket();
    FD_SET(sock, &readfds);

    int sel_result = select(0, &readfds, NULL, NULL, &tv);

    if (sel_result == SOCKET_ERROR) {
        error << "[" << udpManager.getRoleName()
              << " IO] Select failed: " << WSAGetLastError() << endl;
    }

    if (sel_result > 0 && FD_ISSET(sock, &readfds)) {
        Packet received_packet;
        sockaddr_in senderAddr;
        int senderAddrLen = sizeof(senderAddr);
        int bytes =
            recvfrom(sock, (char *)&received_packet, sizeof(received_packet), 0,
                     (SOCKADDR *)&senderAddr, &senderAddrLen);

        if (bytes > 0) {
            udpManager.processReceivedPacket(received_packet, senderAddr);
        }
    }

    udpManager.checkTimeoutAndRetransmit();
}

std::vector<uint8_t> _read_n_bytes(ManagerBase &gbnManager,
                                   size_t required_bytes) {
    std::string roleName = gbnManager.getRoleName();
    std::vector<uint8_t> received_data;

    // 循环直到积累了所需数量的字节
    while (received_data.size() < required_bytes) {
        _processNetworkIO(gbnManager); // 驱动 I/O

        size_t needed = required_bytes - received_data.size();

        // 调用 GBNManager 的流式读取接口
        size_t bytes_read = gbnManager.read(received_data, needed);

        if (bytes_read == 0) {
            // 如果 GBNManager 缓冲区中没有可用数据，则等待
            Sleep(10);
        }
    }

    return received_data;
}

size_t sendData(ManagerBase &udpManager, const std::vector<uint8_t> &data) {
    std::string roleName = udpManager.getRoleName();

    // 长度前缀
    MessageLength_t data_len = (MessageLength_t)data.size();

    // 创建包含长度前缀的完整消息缓冲区
    std::vector<uint8_t> full_message(LENGTH_PREFIX_SIZE + data_len);
    memcpy(full_message.data(), &data_len, LENGTH_PREFIX_SIZE); // 写入长度
    memcpy(full_message.data() + LENGTH_PREFIX_SIZE, data.data(),
           data_len); // 写入载荷

#ifdef DEBUG
    debug << "[" << roleName << " SEND] Raw bytes to send (hex): ";
    for (size_t i = 0; i < full_message.size(); ++i) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", full_message[i]);
        debug << hex;
    }
    debug << endl;
#endif

    size_t full_message_size = full_message.size();
    size_t total_sent_bytes = 0;

    info << "[" << roleName
         << " SEND] Sending message with length prefix: " << data_len
         << " bytes. Total to send: " << full_message_size << endl;

    // 数据分块发送
    for (size_t offset = 0; offset < full_message_size;
         offset += MAX_DATA_SIZE) {
        size_t chunk_size =
            std::min((size_t)MAX_DATA_SIZE, full_message_size - offset);

        bool chunk_sent = false;
        while (!chunk_sent) {
            _processNetworkIO(udpManager);

            const char *buffer = (const char *)(full_message.data() + offset);

            if (udpManager.sendData(buffer, chunk_size)) {
                total_sent_bytes += chunk_size;
                chunk_sent = true;
            } else {
                logger::warn
                    << "[" << roleName
                    << " SEND] Window full during data send. Processing I/O "
                       "and retrying."
                    << endl;
                Sleep(1);
            }
        }
    }

    // 等待所有数据包被确认
    info << "[" << roleName
         << " SEND] All DATA packets enqueued. Waiting for all ACKs..." << endl;
    while (udpManager.isWindowFull()) {
        _processNetworkIO(udpManager);
        Sleep(1);
    }
    info << "[" << roleName
         << " SEND] All DATA acknowledged. Message delivery complete." << endl;

    return data_len;
}

std::vector<uint8_t> recvData(ManagerBase &udpManager) {
    std::string roleName = udpManager.getRoleName();

    // 1. 接收 Length Prefix (4 bytes)
    info << "[" << roleName << " RECV] Waiting for message length prefix ("
         << LENGTH_PREFIX_SIZE << " bytes)..." << endl;

    std::vector<uint8_t> length_bytes =
        _read_n_bytes(udpManager, LENGTH_PREFIX_SIZE);

    if (length_bytes.size() < LENGTH_PREFIX_SIZE) {
        error << "[" << roleName
              << " RECV] Failed to read full length prefix. Aborting." << endl;
        return {};
    }

    MessageLength_t payload_len;
    // 从字节中解析出长度
    memcpy(&payload_len, length_bytes.data(), LENGTH_PREFIX_SIZE);

    if (payload_len == 0) {
        info << "[" << roleName
             << " RECV] Received empty message (Length 0). Skipping payload "
                "read."
             << endl;
        return {};
    }

    // 2. 接收 Payload
    info << "[" << roleName << " RECV] Message length: " << payload_len
         << " bytes. Reading payload..." << endl;
    std::vector<uint8_t> payload = _read_n_bytes(udpManager, payload_len);

    if (payload.size() != payload_len) {
        error << "[" << roleName
              << " RECV] Incomplete payload received! Expected: " << payload_len
              << ", Got: " << payload.size() << ". Data integrity compromised."
              << endl;
        return {};
    }

#ifdef DEBUG
    debug << "[" << roleName << " RECV] Received payload bytes (hex): ";
    for (size_t i = 0; i < payload.size(); ++i) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", payload[i]);
        debug << hex;
    }
    debug << endl;
#endif

    info << "[" << roleName
         << " RECV] Message boundary determined by Length Prefix. Total "
         << payload_len << " bytes successfully received." << endl;

    return payload;
}