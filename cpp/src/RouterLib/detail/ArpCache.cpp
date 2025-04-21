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

    // Ethernet header: broadcast destination, our source
    memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN); // Ensure broadcast
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

    // Retransmit unresolved ARP requests
    for (auto& [ip, entry] : entries) {
        if (!entry.resolved && !entry.pendingPackets.empty()) {
            if (now - entry.lastRequestTime >= resendInterval) {
                if (entry.sentRequests < 7) {
                    // resend ARP
                    const auto& [_, outIface] = entry.pendingPackets.front();
                    Packet req = buildArpRequest(ip, outIface, routingTable);
                    packetSender->sendPacket(req, outIface);
                    entry.sentRequests++;
                    entry.lastRequestTime = now;
                } else {
                    // After 7 failures, send ICMP Host Unreachable for each queued packet
                    for (auto& [pkt, outIface] : entry.pendingPackets) {
                        spdlog::error("ARP failed for IP {} after 7 tries, sending ICMP Host Unreachable", ip);

                        size_t respSize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                        Packet resp(respSize, 0);
                        auto* origEth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
                        auto* origIp  = reinterpret_cast<sr_ip_hdr_t*>(pkt.data() + sizeof(sr_ethernet_hdr_t));

                        auto* reth  = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
                        auto* ip2   = reinterpret_cast<sr_ip_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t));
                        auto* icmp2 = reinterpret_cast<sr_icmp_t3_hdr_t*>(
                                         resp.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                        // Ethernet: dst = original src, src = our interface
                        auto ifaceInfo = routingTable->getRoutingInterface(outIface);
                        memcpy(reth->ether_dhost, origEth->ether_shost, ETHER_ADDR_LEN);
                        memcpy(reth->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
                        reth->ether_type = htons(ethertype_ip);

                        // IP header
                        ip2->ip_v   = 4;
                        ip2->ip_hl  = 5;
                        ip2->ip_tos = 0;
                        ip2->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                        ip2->ip_id  = 0;
                        ip2->ip_off = 0;
                        ip2->ip_ttl = 32;
                        ip2->ip_p   = ip_protocol_icmp;
                        ip2->ip_src = ifaceInfo.ip;
                        ip2->ip_dst = origIp->ip_src;
                        ip2->ip_sum = 0;
                        ip2->ip_sum = cksum(ip2, sizeof(sr_ip_hdr_t));

                        // ICMP Host Unreachable
                        icmp2->icmp_type = 3;
                        icmp2->icmp_code = 1;
                        icmp2->icmp_sum  = 0;
                        icmp2->unused    = 0;
                        icmp2->next_mtu  = 0;
                        size_t dataLen  = std::min<size_t>(ICMP_DATA_SIZE, origIp->ip_hl * 4 + 8);
                        memcpy(icmp2->data, origIp, dataLen);
                        icmp2->icmp_sum = cksum(icmp2, sizeof(sr_icmp_t3_hdr_t));

                        packetSender->sendPacket(resp, outIface); // Use the stored interface
                    }
                    entry.pendingPackets.clear();
                }
            }
        }
    }

    // Expire old entries
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
    for (auto& [pkt, outIface] : entry.pendingPackets) {
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
        memcpy(eth->ether_dhost, mac.data(), ETHER_ADDR_LEN);
        auto outIf = routingTable->getRoutingInterface(outIface);
        memcpy(eth->ether_shost, outIf.mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(pkt, outIface);
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

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    auto& entry = entries[ip];
    if (entry.pendingPackets.empty() && !entry.resolved) {
        entry.timeAdded    = now;
        entry.sentRequests = 0;
    }
    entry.pendingPackets.emplace_back(packet, iface);

    // Immediately send first ARP request
    if (entry.sentRequests == 0) {
        Packet req = buildArpRequest(ip, iface, routingTable);
        packetSender->sendPacket(req, iface);
        entry.sentRequests    = 1;
        entry.lastRequestTime = now;
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}