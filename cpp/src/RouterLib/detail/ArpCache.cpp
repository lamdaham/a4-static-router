#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>
#include <chrono>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>

#include "protocol.h"
#include "utils.h"
#include "IRoutingTable.h"
#include "IPacketSender.h"

// For brevity, assume Packet is defined as:
using Packet = std::vector<uint8_t>;


// --- Helper function to build an ARP request packet ---
static Packet buildArpRequest(uint32_t target_ip, const std::string& iface, std::shared_ptr<IRoutingTable> routingTable) {
    // Get the interface info
    RoutingInterface ifaceInfo = routingTable->getRoutingInterface(iface);

    // Packet size: Ethernet header + ARP header
    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    Packet packet(packet_size, 0);
    uint8_t* buf = packet.data();

    // --- Build Ethernet header ---
    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(buf);
    // Destination MAC: broadcast address
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth_hdr->ether_dhost[i] = 0xff;
    }
    // Source MAC: interface's MAC address
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth_hdr->ether_shost[i] = ifaceInfo.mac[i];
    }
    eth_hdr->ether_type = htons(ethertype_arp);

    // --- Build ARP header ---
    sr_arp_hdr_t* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(buf + sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op_request);
    // Sender hardware address: interface MAC
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        arp_hdr->ar_sha[i] = ifaceInfo.mac[i];
    }
    // Sender IP: interface IP (assumed already in network order)
    arp_hdr->ar_sip = ifaceInfo.ip;
    // Target hardware address: set to zero
    std::fill(std::begin(arp_hdr->ar_tha), std::end(arp_hdr->ar_tha), 0);
    // Target IP: the IP whose MAC is being resolved
    arp_hdr->ar_tip = target_ip;

    return packet;
}

ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout, 
    std::chrono::milliseconds tickInterval, 
    std::chrono::milliseconds resendInterval,
    std::shared_ptr<IPacketSender> packetSender, 
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();

    // Iterate over each ARP entry that is unresolved and has queued packets.
    for (auto &pair : entries) {
        ArpEntry &entry = pair.second;
        if (!entry.resolved && !entry.pendingPackets.empty()) {
            // If enough time has elapsed since the last ARP request...
            if (now - entry.lastRequestTime >= resendInterval) {
                if (entry.sentRequests < 7) {
                    // Use the iface from the first pending packet for the ARP request.
                    std::string outIface = entry.pendingPackets.front().second;
                    Packet arpReq = buildArpRequest(pair.first, outIface, routingTable);
                    packetSender->sendPacket(arpReq, outIface);
                    entry.sentRequests++;
                    entry.lastRequestTime = now;
                    spdlog::info("Resending ARP request for IP {} on iface {} (attempt {})",
                        pair.first, outIface, entry.sentRequests);
                } else {
                    // After 7 attempts: drop all queued packets and (in a full implementation)
                    // generate ICMP host unreachable messages.
                    for (auto &pending : entry.pendingPackets) {
                        spdlog::error("ARP request for IP {} failed after 7 attempts. Dropping queued packet on iface {}",
                                      pair.first, pending.second);
                        // Optionally: generate and send ICMP destination host unreachable here.
                    }
                    entry.pendingPackets.clear();
                }
            }
        }
    }

    // Remove cache entries that have expired.
    std::erase_if(entries, [now, this](const auto& pair) {
        return now - pair.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    // Look for an existing ARP entry.
    auto it = entries.find(ip);
    if (it == entries.end()) {
        // Create a new, resolved entry.
        ArpEntry entry;
        entry.timeAdded = now;
        entry.resolved = true;
        entry.mac = mac;
        entry.sentRequests = 0;
        entries[ip] = entry;
    } else {
        // Update existing entry.
        it->second.resolved = true;
        it->second.mac = mac;
        it->second.timeAdded = now;
    }
    // If there are queued packets, update the Ethernet header's destination MAC and send them.
    auto &entryRef = entries[ip];
    for (auto &pending : entryRef.pendingPackets) {
        Packet packet = pending.first;
        std::string outIface = pending.second;
        if (packet.size() >= sizeof(sr_ethernet_hdr_t)) {
            sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
            for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                eth_hdr->ether_dhost[i] = mac[i];
            }
            packetSender->sendPacket(packet, outIface);
            spdlog::info("Sent queued packet for IP {} out on iface {}", ip, outIface);
        }
    }
    // Clear the pending packet queue once processed.
    entryRef.pendingPackets.clear();
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
    auto it = entries.find(ip);
    if (it == entries.end()) {
        // Create a new entry marked unresolved and queue the packet.
        ArpEntry entry;
        entry.timeAdded = now;
        entry.resolved = false;
        entry.sentRequests = 0;
        entry.lastRequestTime = now;
        entry.pendingPackets.push_back({packet, iface});
        entries[ip] = entry;
    } else {
        // Append the packet to the pending queue.
        it->second.pendingPackets.push_back({packet, iface});
    }
}
