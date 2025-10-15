#pragma once

#include "packet.h"
#include <string>
#include <vector>
#include <winsock2.h>

class ManagerBase {
  public:
    virtual ~ManagerBase() = default;

    // Basic required interface used by network_utils
    virtual SOCKET getSocket() const = 0;
    virtual std::string getRoleName() const = 0;

    // Process raw Packet received from network
    virtual void processReceivedPacket(const Packet &p, const sockaddr_in &senderAddr) = 0;

    // Called periodically to trigger timeout checks / retransmits
    virtual void checkTimeoutAndRetransmit() = 0;

    // Send raw buffer of bytes (upper-layer framing handled by network_utils)
    virtual bool sendData(const char *buffer, int len) = 0;

    // Query whether sender window is full
    virtual bool isWindowFull() const = 0;

    // Stream-like read from application receive buffer
    virtual size_t read(std::vector<uint8_t> &output, size_t max_len) = 0;
};
