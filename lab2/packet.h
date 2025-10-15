#pragma once

#include <cstdint>

constexpr int MAX_DATA_SIZE = 1024; // 数据载荷最大值
constexpr int WINDOW_SIZE = 4;      // 窗口大小
constexpr int TIMEOUT = 500;        // 超时时间，单位为毫秒
constexpr int SEQ_SPACE = 256;      // 序列号空间大小

// 包标志位（可组合使用）
constexpr uint8_t FLAG_ACK = 0x01;  // 确认标志
constexpr uint8_t FLAG_DATA = 0x02; // 数据标志
constexpr uint8_t FLAG_SYN = 0x04;  // 同步标志（可选，用于连接建立）
constexpr uint8_t FLAG_FIN = 0x08;  // 结束标志（可选，用于连接终止）

// TCP-like 全双工数据包结构
struct Packet {
    uint8_t flags;               // 标志位（FLAG_ACK | FLAG_DATA 等）
    uint8_t seq_num;             // 发送序列号
    uint8_t ack_num;             // 确认序列号（捎带确认）
    uint16_t data_length;        // 数据长度
    uint8_t data[MAX_DATA_SIZE]; // 数据载荷
};