#ifndef STATICROUTER_H
#define STATICROUTER_H

#include <cstdint>
#include <vector>
#include <chrono>
#include <string>
#include <memory>

// Include the interfaces for packet sending, routing table access, and ARP cache.
#include "../IPacketSender.h"
#include "../IRoutingTable.h"
#include "ArpCache.h"  // Note: our ARP cache implementation lives in ArpCache.h

// IStaticRouter interface (defined in IStaticRouter.h) is extended here.
class StaticRouter : public IStaticRouter {
public:
    // Constructor: you pass pointers to a routing table and packet sender,
    // as well as timing parameters for ARP behavior.
    StaticRouter(std::shared_ptr<IRoutingTable> rt,
                 std::shared_ptr<IPacketSender> sender,
                 std::chrono::seconds arpCacheTimeout,
                 std::chrono::milliseconds arpResendInterval,
                 std::chrono::seconds arpRequestTimeout);

    // Process an incoming packet; the 'inInterface' tells you the input interface.
    void handlePacket(const std::vector<uint8_t>& packet, const std::string& inInterface) override;
    
private:
    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IArpCache> arpCache;

    // Timing parameters for ARP retransmission.
    std::chrono::milliseconds resendInterval;
    std::chrono::seconds requestTimeout;

    // Internal helpers.
    void processArpPacket(const std::vector<uint8_t>& packet, const std::string& inInterface);
    void processIpPacket(const std::vector<uint8_t>& packet, const std::string& inInterface);

    // ICMP message generators.
    void sendIcmpEchoReply(const std::vector<uint8_t>& ipPacket, const std::string& inInterface);
    void sendIcmpError(uint8_t type, uint8_t code,
                       const std::vector<uint8_t>& originalPacket,
                       const std::string& inInterface);
};

#endif // STATICROUTER_H
