#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <chrono>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>
#include <vector>
#include <string>

#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"

// Define Packet as a vector of bytes for convenience
using Packet = std::vector<uint8_t>;

// Extended ArpEntry definition with all needed fields.
struct ArpEntry {
    std::chrono::steady_clock::time_point timeAdded;
    bool resolved = false; // Indicates whether this entry is resolved.
    mac_addr mac; // The MAC address associated with the IP address.
    // Queue of packets waiting for ARP resolution; each element pairs a packet with the outgoing interface.
    std::vector<std::pair<Packet, std::string>> pendingPackets;
    int sentRequests = 0; // Number of ARP request retransmissions.
    std::chrono::steady_clock::time_point lastRequestTime; // When the last ARP request was sent.
};

class ArpCache {
public:
    ArpCache(
        std::chrono::milliseconds entryTimeout,
        std::chrono::milliseconds tickInterval,
        std::chrono::milliseconds resendInterval,
        std::shared_ptr<IPacketSender> packetSender, 
        std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache();

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac);

    std::optional<mac_addr> getEntry(uint32_t ip);

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface);

private:
    void loop();

    std::chrono::milliseconds entryTimeout;
    std::chrono::milliseconds tickInterval;
    std::chrono::milliseconds resendInterval;

    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::mutex mutex;
    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
};

#endif // ARPCACHE_H
