#pragma once

#include "../logger/logger.h"
#include "ManagerBase.h"
#include <vector>
#include <winsock2.h>

using logger::error;
using logger::info;
#ifdef DEBUG
using logger::debug;
#endif
using std::endl;

using MessageLength_t = uint32_t;
constexpr size_t LENGTH_PREFIX_SIZE = sizeof(MessageLength_t);

// 简化的接口：直接使用 Manager 的 send/read
// Manager 内部的后台线程会处理所有网络 I/O

size_t sendData(ManagerBase &udpManager, const std::vector<uint8_t> &data);
std::vector<uint8_t> recvData(ManagerBase &udpManager);
