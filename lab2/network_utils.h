#pragma once

#include "../logger/logger.h"
#include "GBNmanager.h"
#include "ManagerBase.h" // use abstract manager base so network_utils works with any manager
#include <winsock2.h>
#include <ws2tcpip.h>

using logger::error;
using logger::info;
#ifdef DEBUG
using logger::debug;
#endif
using std::endl;

using MessageLength_t = uint32_t;
constexpr size_t LENGTH_PREFIX_SIZE = sizeof(MessageLength_t);

void _processNetworkIO(ManagerBase &udpManager, DWORD waitTimeMs);
std::vector<uint8_t> _read_n_bytes(ManagerBase &gbnManager,
                                   size_t required_bytes);

size_t sendData(ManagerBase &udpManager, const std::vector<uint8_t> &data);
std::vector<uint8_t> recvData(ManagerBase &udpManager);
