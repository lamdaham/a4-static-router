#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache, 
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
    , packetSender(packetSender)
    , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    std::unique_lock lock(mutex);

    // Validate packet contains an Ethernet header
    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }
    
    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t etherType = ntohs(eth_hdr->ether_type);

    if (etherType == ethertype_arp) {
        // --- ARP packet processing ---
        spdlog::info("Received ARP packet.");
        // Here you would check if the ARP request is meant for one of your router’s IPs
        // and, if so, construct and send an appropriate ARP reply.
        // You may also update the ARP cache if you receive a valid ARP reply.
        return;
    }
    else if (etherType == ethertype_ip) {
        // --- IP packet processing ---
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            spdlog::error("Packet too small for IP header.");
            return;
        }
        
        sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        
        // Validate IP checksum
        uint16_t savedSum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        uint16_t computedSum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        if (computedSum != savedSum) {
            spdlog::error("Invalid IP checksum.");
            return;
        }
        ip_hdr->ip_sum = savedSum; // restore for now (will update after modifying)

        // Check if the destination IP matches one of the router's interfaces
        bool destinedForRouter = false;
        auto routingInterfaces = routingTable->getRoutingInterfaces();
        for (const auto& kv : routingInterfaces) {
            if (ip_hdr->ip_dst == kv.second.ip) {
                destinedForRouter = true;
                break;
            }
        }
        if (destinedForRouter) {
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                // pointer to ICMP header + data
                uint8_t* icmp_buf = packet.data() 
                                 + sizeof(sr_ethernet_hdr_t)
                                 + ip_hdr->ip_hl * 4;
                sr_icmp_hdr_t* icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(icmp_buf);
        
                // only handle echo requests (type 8, code 0)
                if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
                    // 1) swap Ethernet addresses
                    mac_addr tmp_mac;
                    memcpy(tmp_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_dhost, tmp_mac.data(), ETHER_ADDR_LEN);
        
                    // 2) swap IP addresses
                    uint32_t tmp_ip = ip_hdr->ip_src;
                    ip_hdr->ip_src = ip_hdr->ip_dst;
                    ip_hdr->ip_dst = tmp_ip;
        
                    // 3) set TTL and recompute IP checksum
                    ip_hdr->ip_ttl = 64;
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        
                    // 4) change ICMP to echo‑reply (type 0) and zero checksum
                    icmp_hdr->icmp_type = 0;
                    icmp_hdr->icmp_code = 0;
                    icmp_hdr->icmp_sum = 0;
        
                    // compute ICMP checksum over the entire ICMP payload
                    int icmp_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);
        
                    // 5) send it back out
                    packetSender->sendPacket(packet, iface);
                    return;
                }
            }
            // (optionally handle TCP/UDP port‑unreachable here)
            return;
        }
        
        
        // --- Forwarding the IP Packet ---
        // Decrement TTL and check for expiration
        if (--ip_hdr->ip_ttl == 0) {
            spdlog::error("TTL expired: sending ICMP Time Exceeded.");
            // Generate and send an ICMP Time Exceeded message back to the source.
            return;
        }
        // Recompute the checksum after decrementing TTL
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        
        // Look up the routing table for a matching entry using longest prefix match
        auto routeOpt = routingTable->getRoutingEntry(ip_hdr->ip_dst);
        if (!routeOpt.has_value()) {
            spdlog::error("No routing entry found for destination IP.");
            // Optionally, send an ICMP Destination Network Unreachable message.
            return;
        }
        RoutingEntry route = routeOpt.value();
        
        // Determine the next-hop IP (if the gateway field is zero, use the destination IP)
        uint32_t nextHop = (route.gateway == 0) ? ip_hdr->ip_dst : route.gateway;

        // Check ARP cache for the next-hop MAC address.
        auto macOpt = arpCache->getEntry(nextHop);
        if (!macOpt.has_value()) {
            spdlog::info("No ARP entry for next hop. Queuing packet.");
            arpCache->queuePacket(nextHop, packet, route.iface);
            // An ARP request will be sent by the ArpCache module.
            return;
        }
        mac_addr nextHopMac = macOpt.value();
        
        // Update the Ethernet header:
        // Set destination MAC to next-hop's MAC.
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            eth_hdr->ether_dhost[i] = nextHopMac[i];
        }
        // Set source MAC to the MAC address of the outgoing interface.
        RoutingInterface outIface = routingTable->getRoutingInterface(route.iface);
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            eth_hdr->ether_shost[i] = outIface.mac[i];
        }
        
        // Send the packet on the designated interface.
        packetSender->sendPacket(packet, route.iface);
        spdlog::info("Forwarded packet via interface {}", route.iface);
    }
    else {
        spdlog::error("Unsupported Ethernet type: {}", etherType);
    }
}