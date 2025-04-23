#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>
#include <chrono>
#include <algorithm>
#include <arpa/inet.h>

#include "protocol.h"
#include "utils.h"
#include "IRoutingTable.h"
#include "IPacketSender.h"

using Packet = std::vector<uint8_t>;

static Packet buildArpRequest(uint32_t target_ip,
                              const std::string& iface,
                              std::shared_ptr<IRoutingTable> routingTable) {
    auto ifInfo = routingTable->getRoutingInterface(iface);
    Packet pkt(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), 0);
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
    auto* arp = reinterpret_cast<sr_arp_hdr_t*>(pkt.data() + sizeof(sr_ethernet_hdr_t));

    // Ethernet header - broadcast destination
    memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(eth->ether_shost, ifInfo.mac.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_arp);

    // ARP header
    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = sizeof(uint32_t);
    arp->ar_op  = htons(arp_op_request);
    memcpy(arp->ar_sha, ifInfo.mac.data(), ETHER_ADDR_LEN);
    arp->ar_sip = ifInfo.ip;
    memset(arp->ar_tha, 0, ETHER_ADDR_LEN);
    arp->ar_tip = target_ip;

    return pkt;
}

ArpCache::ArpCache(std::chrono::milliseconds entryTimeout,
                 std::chrono::milliseconds tickInterval,
                 std::chrono::milliseconds resendInterval,
                 std::shared_ptr<IPacketSender> packetSender,
                 std::shared_ptr<IRoutingTable> routingTable)
  : entryTimeout(entryTimeout)
  , tickInterval(tickInterval)
  , resendInterval(resendInterval)
  , packetSender(std::move(packetSender))
  , routingTable(std::move(routingTable))
{
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) thread->join();
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();

    // Process each unresolved ARP entry with queued packets
    for (auto& [ip, entry] : entries) {
        if (!entry.resolved && !entry.pendingPackets.empty()) {
            if (now - entry.lastRequestTime >= resendInterval) {
                if (entry.sentRequests < 7) {
                    // Resend ARP request using the outIface from the first queued packet.
                    auto& pend = entry.pendingPackets.front();
                    Packet req = buildArpRequest(ip, pend.outIface, routingTable);
                    packetSender->sendPacket(req, pend.outIface);
                    entry.sentRequests++;
                    entry.lastRequestTime = now;
                } else {
                    // For each pending packet, send a separate ICMP Destination Unreachable message.
                    for (auto& pend : entry.pendingPackets) {
                        // Retrieve the interface information for the incoming packet.
                        auto ifInfo = routingTable->getRoutingInterface(pend.inIface);
                        size_t icmp_hdr_size = 8;  // Expected ICMP header length: 8 bytes.
                        size_t respSize = sizeof(sr_ethernet_hdr_t)
                                          + sizeof(sr_ip_hdr_t)
                                          + icmp_hdr_size;
                        std::vector<uint8_t> resp(respSize, 0);
                        
                        // Build Ethernet header.
                        auto* rEth = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
                        // Use the original packet's source MAC as destination.
                        const auto* origEth = reinterpret_cast<const sr_ethernet_hdr_t*>(pend.pkt.data());
                        memcpy(rEth->ether_dhost, origEth->ether_shost, ETHER_ADDR_LEN);
                        memcpy(rEth->ether_shost, ifInfo.mac.data(),   ETHER_ADDR_LEN);
                        rEth->ether_type = htons(ethertype_ip);
                        
                        // Build IP header.
                        auto* rIp = reinterpret_cast<sr_ip_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t));
                        // For the unreachable message, the source IP is the device’s IP; the destination is the original packet’s source.
                        const auto* origIp = reinterpret_cast<const sr_ip_hdr_t*>(pend.pkt.data() + sizeof(sr_ethernet_hdr_t));
                        rIp->ip_v   = 4;
                        rIp->ip_hl  = 5;
                        rIp->ip_tos = 0;
                        rIp->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_hdr_size);
                        rIp->ip_id  = 0;
                        rIp->ip_off = 0;
                        rIp->ip_ttl = 32;
                        rIp->ip_p   = ip_protocol_icmp;
                        rIp->ip_src = ifInfo.ip;
                        rIp->ip_dst = origIp->ip_src;
                        rIp->ip_sum = 0;
                        rIp->ip_sum = cksum(rIp, sizeof(sr_ip_hdr_t));
                        
                        // Build ICMP header.
                        auto* rIcmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data() 
                                                  + sizeof(sr_ethernet_hdr_t)
                                                  + sizeof(sr_ip_hdr_t));
                        rIcmp->icmp_type = 3; // Destination Unreachable.
                        rIcmp->icmp_code = 0; // Net Unreachable.
                        rIcmp->icmp_sum  = 0;
                        rIcmp->unused    = 0;
                        rIcmp->next_mtu  = 0;
                        // Copy the original IP header + first 8 bytes.
                        size_t origDataLen = std::min<size_t>(ICMP_DATA_SIZE, static_cast<size_t>(origIp->ip_hl * 4 + 8));
                        memcpy(rIcmp->data, pend.pkt.data() + sizeof(sr_ethernet_hdr_t), origDataLen);
                        rIcmp->icmp_sum = cksum(rIcmp, icmp_hdr_size);
                        
                        // Send the ICMP unreachable response for this queued packet.
                        packetSender->sendPacket(resp, pend.inIface);
                    }
                    entry.pendingPackets.clear();
                }
            }
        }
    }

    // Remove expired entries.
    std::erase_if(entries, [&](auto const& kv) {
        return now - kv.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    auto& entry = entries[ip];
    entry.timeAdded    = now;
    entry.resolved     = true;
    entry.mac          = mac;
    entry.sentRequests = 0;

    // send any queued packets
    for (auto& pend : entry.pendingPackets) {
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pend.pkt.data());
        memcpy(eth->ether_dhost, mac.data(), ETHER_ADDR_LEN);
        auto outIf = routingTable->getRoutingInterface(pend.outIface);
        memcpy(eth->ether_shost, outIf.mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(pend.pkt, pend.outIface);
    }
    entry.pendingPackets.clear();
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);
    auto it = entries.find(ip);
    if (it != entries.end() && it->second.resolved) {
        return it->second.mac;
    }
    return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, 
                           const std::string& inIface, const std::string& outIface) {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    auto& entry = entries[ip];
    if (entry.pendingPackets.empty() && !entry.resolved) {
        entry.timeAdded = now;
        entry.sentRequests = 0;
    }
    entry.pendingPackets.push_back({packet, inIface, outIface});

    // Immediately send initial ARP request if not already sent.
    if (entry.sentRequests == 0) {
        Packet req = buildArpRequest(ip, outIface, routingTable);
        packetSender->sendPacket(req, outIface);
        entry.sentRequests = 1;
        entry.lastRequestTime = now;
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}