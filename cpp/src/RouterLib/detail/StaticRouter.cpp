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
{}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    std::unique_lock lock(mutex);

    // Must have at least an Ethernet header
    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet too small for Ethernet header");
        return;
    }

    auto *eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t etherType = ntohs(eth_hdr->ether_type);

    //
    // --- ARP Handling ---
    //
    if (etherType == ethertype_arp) {
        auto *arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(
            packet.data() + sizeof(sr_ethernet_hdr_t));

        uint16_t op  = ntohs(arp_hdr->ar_op);
        uint32_t sip = ntohl(arp_hdr->ar_sip);
        uint32_t tip = ntohl(arp_hdr->ar_tip);

        // Our interface info for this ingress port
        auto ifInfo = routingTable->getRoutingInterface(iface);

        // ARP Request for one of our IPs → send reply
        if (op == arp_op_request && tip == ifInfo.ip) {
            // Build ARP reply
            std::vector<uint8_t> reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            auto *reth = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
            auto *rarp = reinterpret_cast<sr_arp_hdr_t*>(reply.data() + sizeof(sr_ethernet_hdr_t));

            // Ethernet header: swap src/dst, set type
            std::memcpy(reth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            std::memcpy(reth->ether_shost, ifInfo.mac.data(),  ETHER_ADDR_LEN);
            reth->ether_type = htons(ethertype_arp);

            // ARP header
            rarp->ar_hrd = htons(arp_hrd_ethernet);
            rarp->ar_pro = htons(ethertype_ip);
            rarp->ar_hln = ETHER_ADDR_LEN;
            rarp->ar_pln = sizeof(uint32_t);
            rarp->ar_op  = htons(arp_op_reply);

            std::memcpy(rarp->ar_sha, ifInfo.mac.data(),            ETHER_ADDR_LEN);
            rarp->ar_sip = htonl(ifInfo.ip);
            std::memcpy(rarp->ar_tha, arp_hdr->ar_sha,              ETHER_ADDR_LEN);
            rarp->ar_tip = arp_hdr->ar_sip;

            packetSender->sendPacket(reply, iface);
            return;
        }
        // ARP Reply → learn and drain queue
        else if (op == arp_op_reply) {
            mac_addr mac;
            std::memcpy(mac.data(), arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arpCache->addEntry(ntohl(arp_hdr->ar_sip), mac);
            return;
        }
        return;
    }

    //
    // --- IP Handling ---
    //
    if (etherType == ethertype_ip) {
        // Must have full IP header
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            spdlog::error("Packet too small for IP");
            return;
        }

        auto *ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(
            packet.data() + sizeof(sr_ethernet_hdr_t));

        // Validate checksum
        uint16_t orig_sum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        uint16_t calc_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        if (calc_sum != orig_sum) {
            spdlog::error("Bad IP checksum");
            return;
        }
        ip_hdr->ip_sum = orig_sum;

        // Is this destined for one of our interfaces?
        bool forUs = false;
        for (auto const& [name, ifaceInfo] : routingTable->getRoutingInterfaces()) {
            if (ip_hdr->ip_dst == ifaceInfo.ip) {
                forUs = true;
                break;
            }
        }

        if (forUs) {
            // --- ICMP Echo Reply ---
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                // Locate ICMP header
                uint8_t* icmp_buf = packet.data()
                    + sizeof(sr_ethernet_hdr_t)
                    + ip_hdr->ip_hl * 4;
                auto *icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(icmp_buf);

                // Echo request? type=8, code=0
                if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
                    // 1) swap Ethernet MACs
                    mac_addr tmp_mac;
                    std::memcpy(tmp_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    std::memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
                    std::memcpy(eth_hdr->ether_dhost, tmp_mac.data(),       ETHER_ADDR_LEN);

                    // 2) swap IPs
                    uint32_t tmp_ip = ip_hdr->ip_src;
                    ip_hdr->ip_src = ip_hdr->ip_dst;
                    ip_hdr->ip_dst = tmp_ip;

                    // 3) reset TTL & IP checksum
                    ip_hdr->ip_ttl = 64;
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

                    // 4) set ICMP to echo‑reply & recompute checksum
                    icmp_hdr->icmp_type = 0;
                    icmp_hdr->icmp_code = 0;
                    icmp_hdr->icmp_sum  = 0;
                    int icmp_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);

                    // 5) send back out
                    packetSender->sendPacket(packet, iface);
                    return;
                }
            }
            // --- Port Unreachable for TCP/UDP to us ---
            if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
                spdlog::info("Port unreachable for protocol {}", ip_hdr->ip_p);
                // (Similar ICMP type3/code3 construction would go here)
                return;
            }
            return;
        }

        //
        // --- Forwarding ---
        //

        // TTL decrement + check
        if (--ip_hdr->ip_ttl == 0) {
            spdlog::error("TTL expired, should send Time Exceeded");
            // (ICMP type11/code0 would go here)
            return;
        }
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        // Longest‐prefix match
        auto routeOpt = routingTable->getRoutingEntry(ip_hdr->ip_dst);
        if (!routeOpt) {
            spdlog::error("No route to {}", ntohl(ip_hdr->ip_dst));
            // (ICMP type3/code0 would go here)
            return;
        }
        auto route = *routeOpt;
        uint32_t nextHop = route.gateway ? route.gateway : ip_hdr->ip_dst;

        // ARP lookup
        auto macOpt = arpCache->getEntry(nextHop);
        if (!macOpt) {
            spdlog::info("Queueing packet for ARP resolution of {}", ntohl(nextHop));
            arpCache->queuePacket(nextHop, packet, route.iface);
            return;
        }
        mac_addr nh_mac = *macOpt;

        // Rewrite Ethernet header
        std::memcpy(eth_hdr->ether_dhost, nh_mac.data(), ETHER_ADDR_LEN);
        auto outInfo = routingTable->getRoutingInterface(route.iface);
        std::memcpy(eth_hdr->ether_shost, outInfo.mac.data(), ETHER_ADDR_LEN);

        packetSender->sendPacket(packet, route.iface);
        spdlog::info("Forwarded packet via {}", route.iface);
        return;
    }

    spdlog::error("Unsupported ethertype: {}", etherType);
}
