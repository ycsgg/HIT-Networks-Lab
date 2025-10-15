#include "network_utils.h"

// 辅助函数：阻塞读取指定数量的字节
// Manager 后台线程会自动处理 I/O，我们只需要等待数据到达
std::vector<uint8_t> _read_n_bytes(ManagerBase &manager, size_t required_bytes) {
    std::string roleName = manager.getRoleName();
    std::vector<uint8_t> received_data;
    received_data.reserve(required_bytes);

    // 循环直到读取到所需的字节数
    while (received_data.size() < required_bytes) {
        size_t needed = required_bytes - received_data.size();
        size_t bytes_read = manager.read(received_data, needed);

        if (bytes_read == 0) {
            // 没有数据可读，短暂等待后台线程接收数据
            Sleep(10);
        }
    }

    return received_data;
}

size_t sendData(ManagerBase &manager, const std::vector<uint8_t> &data) {
    std::string roleName = manager.getRoleName();

    // 长度前缀
    MessageLength_t data_len = (MessageLength_t)data.size();

    // 创建包含长度前缀的完整消息缓冲区
    std::vector<uint8_t> full_message(LENGTH_PREFIX_SIZE + data_len);
    memcpy(full_message.data(), &data_len, LENGTH_PREFIX_SIZE);
    memcpy(full_message.data() + LENGTH_PREFIX_SIZE, data.data(), data_len);

#ifdef DEBUG
    debug << "[" << roleName << " SEND] Raw bytes to send (hex): ";
    for (size_t i = 0; i < full_message.size(); ++i) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", full_message[i]);
        debug << hex;
    }
    debug << endl;
#endif

    info << "[" << roleName << " SEND] Sending message with length prefix: "
         << data_len << " bytes. Total to send: " << full_message.size() << endl;

    // 数据分块发送（Manager 后台线程会处理实际传输和重传）
    for (size_t offset = 0; offset < full_message.size(); offset += MAX_DATA_SIZE) {
        size_t chunk_size = std::min((size_t)MAX_DATA_SIZE, full_message.size() - offset);
        const char *buffer = (const char *)(full_message.data() + offset);

        // 发送到 Manager 的发送队列
        while (!manager.sendData(buffer, chunk_size)) {
            // 队列满，等待后台线程处理
            Sleep(10);
        }
    }

    // 等待窗口变空（所有数据已确认）
    info << "[" << roleName << " SEND] All DATA enqueued. Waiting for ACKs..." << endl;
    while (manager.isWindowFull()) {
        Sleep(10);
    }
    info << "[" << roleName << " SEND] Message delivery complete." << endl;

    return data_len;
}

std::vector<uint8_t> recvData(ManagerBase &manager) {
    std::string roleName = manager.getRoleName();

    // 1. 接收长度前缀 (4 bytes)
    info << "[" << roleName << " RECV] Waiting for message length prefix ("
         << LENGTH_PREFIX_SIZE << " bytes)..." << endl;

    std::vector<uint8_t> length_bytes = _read_n_bytes(manager, LENGTH_PREFIX_SIZE);

    if (length_bytes.size() < LENGTH_PREFIX_SIZE) {
        error << "[" << roleName << " RECV] Failed to read full length prefix." << endl;
        return {};
    }

    MessageLength_t payload_len;
    memcpy(&payload_len, length_bytes.data(), LENGTH_PREFIX_SIZE);

    if (payload_len == 0) {
        info << "[" << roleName << " RECV] Received empty message (Length 0)." << endl;
        return {};
    }

    // 2. 接收 Payload
    info << "[" << roleName << " RECV] Message length: " << payload_len
         << " bytes. Reading payload..." << endl;
    std::vector<uint8_t> payload = _read_n_bytes(manager, payload_len);

    if (payload.size() != payload_len) {
        error << "[" << roleName << " RECV] Incomplete payload received! Expected: "
              << payload_len << ", Got: " << payload.size() << endl;
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

    info << "[" << roleName << " RECV] Total " << payload_len
         << " bytes successfully received." << endl;

    return payload;
}