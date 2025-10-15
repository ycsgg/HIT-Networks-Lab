#pragma once

#include <cstdint>

constexpr int MAX_DATA_SIZE = 1024; // 数据载荷最大值
constexpr int WINDOW_SIZE = 4;      // 窗口大小
constexpr int TIMEOUT = 500;        // 超时时间，单位为毫秒
constexpr int SEQ_SPACE = 256;      // 序列号空间大小

enum FrameType {
    DATA = 0, // 数据帧
    ACK = 1,  // 确认帧
};

struct Packet {
    // 用 uint8_t 而不是 enum FrameType 来确保结构体大小一致
    uint8_t type;                // 帧类型
    uint8_t seq_num;             // 序列号
    uint8_t ack_num;             // 确认号
    uint16_t data_length;        // 数据长度
    uint8_t data[MAX_DATA_SIZE]; // 数据载荷
};