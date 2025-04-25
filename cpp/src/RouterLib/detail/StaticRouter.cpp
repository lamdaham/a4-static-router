#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>
#include <arpa/inet.h>

#include "protocol.h"
#include "utils.h"

struct minimal_icmp {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t unused;
};

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache,
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
  : routingTable(std::move(routingTable))
  , packetSender(std::move(packetSender))
  , arpCache(std::move(arpCache))
{}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    std::unique_lock lock(mutex);

    // 1) Ethernet header present?
    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet too small for Ethernet header");
        return;
    }
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t ethType = ntohs(eth->ether_type);

    // --- ARP Handling ---
    if (ethType == ethertype_arp) {
        auto* arp = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        uint16_t op  = ntohs(arp->ar_op);
        uint32_t tip = arp->ar_tip;

        auto ifInfo = routingTable->getRoutingInterface(iface);

        if (op == arp_op_request && tip == ifInfo.ip) {
            // Build ARP reply
            std::vector<uint8_t> reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), 0);
            auto* reth = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
            auto* rarp = reinterpret_cast<sr_arp_hdr_t*>(reply.data() + sizeof(sr_ethernet_hdr_t));

            // Ethernet header
            memcpy(reth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
            memcpy(reth->ether_shost, ifInfo.mac.data(),   ETHER_ADDR_LEN);
            reth->ether_type = htons(ethertype_arp);

            // ARP header
            rarp->ar_hrd = htons(arp_hrd_ethernet);
            rarp->ar_pro = htons(ethertype_ip);
            rarp->ar_hln = ETHER_ADDR_LEN;
            rarp->ar_pln = sizeof(uint32_t);
            rarp->ar_op  = htons(arp_op_reply);
            memcpy(rarp->ar_sha, ifInfo.mac.data(),       ETHER_ADDR_LEN);
            rarp->ar_sip = ifInfo.ip;
            memcpy(rarp->ar_tha, arp->ar_sha,             ETHER_ADDR_LEN);
            rarp->ar_tip = arp->ar_sip;

            packetSender->sendPacket(reply, iface);
        }
        else if (op == arp_op_reply  &&  arp->ar_tip == ifInfo.ip) {
            mac_addr mac;
            memcpy(mac.data(), arp->ar_sha, ETHER_ADDR_LEN);
            arpCache->addEntry(arp->ar_sip, mac);
        }
        return;
    }

    // --- IP Handling ---
    if (ethType == ethertype_ip) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            spdlog::error("Packet too small for IP header");
            return;
        }
        auto* ip = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

        // Validate checksum
        uint16_t origSum = ip->ip_sum;
        ip->ip_sum = 0;
        if (cksum(ip, ip->ip_hl * 4) != origSum) {
            spdlog::error("Invalid IP checksum");
            return;
        }
        ip->ip_sum = origSum;

        // TTL check before any modifications; silently drop if TTL==0
        if (ip->ip_ttl == 0) {
            return;
        }

        // --- Is this packet for one of our IPs? ---
        bool toMe = false;
        for (auto const& kv : routingTable->getRoutingInterfaces()) {
            if (ip->ip_dst == kv.second.ip) {
                toMe = true;
                break;
            }
        }
        if (toMe) {
            // Handle packets destined for us.
            // For example, process ICMP Echo Request.
            if (ip->ip_p == ip_protocol_icmp &&
                packet.size() >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
            {
                auto* icmp = reinterpret_cast<sr_icmp_hdr_t*>(packet.data()
                                  + sizeof(sr_ethernet_hdr_t)
                                  + sizeof(sr_ip_hdr_t));
                if (icmp->icmp_type == 8 && icmp->icmp_code == 0) {
                    auto ifInfo = routingTable->getRoutingInterface(iface);
                    // Swap Ethernet addresses
                    uint8_t tmp[ETHER_ADDR_LEN];
                    memcpy(tmp, eth->ether_shost, ETHER_ADDR_LEN);
                    memcpy(eth->ether_shost, eth->ether_dhost, ETHER_ADDR_LEN);
                    memcpy(eth->ether_dhost, tmp, ETHER_ADDR_LEN);

                    // Swap IP addresses
                    uint32_t sip = ip->ip_src;
                    ip->ip_src = ip->ip_dst;
                    ip->ip_dst = sip;
                    ip->ip_ttl = 64;
                    ip->ip_sum = 0;
                    ip->ip_sum = cksum(ip, ip->ip_hl * 4);

                    // Build ICMP Echo Reply
                    icmp->icmp_type = 0;
                    icmp->icmp_code = 0;
                    icmp->icmp_sum  = 0;
                    int icmpLen = ntohs(ip->ip_len) - (ip->ip_hl * 4);
                    icmp->icmp_sum = cksum(icmp, icmpLen);

                    packetSender->sendPacket(packet, iface);
                }
            }
            // UDP/TCP to us → Port Unreachable
            else if (ip->ip_p == ip_protocol_udp || ip->ip_p == ip_protocol_tcp) {
                // First, get the interface of the incoming packet.
                RoutingInterface inInfo = routingTable->getRoutingInterface(iface);
                RoutingInterface outInfo;
                std::string outIface;

                // Find which interface owns the destination IP
                bool found = false;
                for (auto const& kv : routingTable->getRoutingInterfaces()) {
                    if (ip->ip_dst == kv.second.ip) {
                        outInfo = kv.second;
                        outIface = kv.first;
                        found = true;
                        break;
                    }
                }

                // Fallback to incoming interface if not found (shouldn't happen for "toMe" packets)
                if (!found) {
                    outInfo = inInfo;
                    outIface = iface;
                }

  
                
                // Build ICMP Port Unreachable message.
                size_t sz = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                std::vector<uint8_t> resp(sz, 0);
                auto* rEth = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
                auto* rIp = reinterpret_cast<sr_ip_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t));
                auto* rIcmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data() +
                                                sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                
                // Ethernet header: reply to sender using the source MAC of the selected interface.
                memcpy(rEth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
                memcpy(rEth->ether_shost, outInfo.mac.data(), ETHER_ADDR_LEN);
                rEth->ether_type = htons(ethertype_ip);
                
                // Build IP header.
                rIp->ip_v   = 4;
                rIp->ip_hl  = 5;
                rIp->ip_tos = 0;
                rIp->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                rIp->ip_id  = 0;
                rIp->ip_off = 0;
                rIp->ip_ttl = 32;
                rIp->ip_p   = ip_protocol_icmp;
                rIp->ip_src = outInfo.ip;   // Use the IP of the interface that owns the destination.
                rIp->ip_dst = ip->ip_src;
                rIp->ip_sum = 0;
                rIp->ip_sum = cksum(rIp, sizeof(sr_ip_hdr_t));
                
                // Build ICMP Port Unreachable (Type 3 Code 3).
                rIcmp->icmp_type = 3;
                rIcmp->icmp_code = 3;
                rIcmp->icmp_sum  = 0;
                rIcmp->unused    = 0;
                rIcmp->next_mtu  = 0;
                size_t dataLen = std::min<size_t>(ICMP_DATA_SIZE, ip->ip_hl * 4 + 8);
                memcpy(rIcmp->data, ip, dataLen);
                rIcmp->icmp_sum = cksum(rIcmp, sizeof(sr_icmp_t3_hdr_t));
                
                packetSender->sendPacket(resp, outIface);
                return;
            }
            // Otherwise, silently drop packet destined for us.
            return;
        }

        // --- Not for us: prepare to forward ---
        // Save original IP header + first 8 bytes for potential ICMP errors
        size_t origDataLen = std::min<size_t>(ICMP_DATA_SIZE, static_cast<size_t>(ip->ip_hl * 4 + 8));
        std::vector<uint8_t> original_ip_data(origDataLen);
        memcpy(original_ip_data.data(), ip, origDataLen);

        // TTL expired → ICMP Time Exceeded
        if (ip->ip_ttl == 1) {
            auto ifInfo = routingTable->getRoutingInterface(iface);
            size_t respSize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            std::vector<uint8_t> resp(respSize, 0);

            auto* rEth  = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
            auto* rIp   = reinterpret_cast<sr_ip_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t));
            auto* rIcmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data()
                                  + sizeof(sr_ethernet_hdr_t)
                                  + sizeof(sr_ip_hdr_t));

            // Ethernet
            memcpy(rEth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
            memcpy(rEth->ether_shost, ifInfo.mac.data(),   ETHER_ADDR_LEN);
            rEth->ether_type = htons(ethertype_ip);

            // IP
            rIp->ip_v   = 4;
            rIp->ip_hl  = 5;
            rIp->ip_tos = 0;
            rIp->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            rIp->ip_id  = 0;
            rIp->ip_off = 0;
            rIp->ip_ttl = 32;
            rIp->ip_p   = ip_protocol_icmp;
            rIp->ip_src = ifInfo.ip;
            rIp->ip_dst = ip->ip_src;
            rIp->ip_sum = 0;
            rIp->ip_sum = cksum(rIp, sizeof(sr_ip_hdr_t));

            // ICMP Type 11 Code 0 (Time Exceeded)
            rIcmp->icmp_type = 11;
            rIcmp->icmp_code = 0;
            rIcmp->icmp_sum  = 0;
            rIcmp->unused    = 0;
            rIcmp->next_mtu  = 0;
            memcpy(rIcmp->data, original_ip_data.data(), origDataLen);
            rIcmp->icmp_sum = cksum(rIcmp, sizeof(sr_icmp_t3_hdr_t));

            packetSender->sendPacket(resp, iface);
            return;
        }

        // Normal forward: decrement TTL and update checksum
        ip->ip_ttl--;
        ip->ip_sum = 0;
        ip->ip_sum = cksum(ip, ip->ip_hl * 4);

        // Route lookup
        auto entryOpt = routingTable->getRoutingEntry(ip->ip_dst);
        // Replace the Destination Net Unreachable section with:
        if (!entryOpt) {
            auto ifInfo = routingTable->getRoutingInterface(iface);
            
            // Calculate space needed for original IP header + 8 bytes
            size_t origDataLen = std::min<size_t>(ICMP_DATA_SIZE, static_cast<size_t>(ip->ip_hl * 4 + 8));
            
            // Use full ICMP header structure that includes data portion
            size_t icmp_hdr_size = sizeof(sr_icmp_t3_hdr_t);
            size_t respSize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_hdr_size;
            std::vector<uint8_t> resp(respSize, 0);
        
            auto* e2 = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
            auto* ip3 = reinterpret_cast<sr_ip_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t));
            auto* ic3 = reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
            // Ethernet header
            memcpy(e2->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
            memcpy(e2->ether_shost, ifInfo.mac.data(), ETHER_ADDR_LEN);
            e2->ether_type = htons(ethertype_ip);
        
            // IP header
            ip3->ip_v = 4;
            ip3->ip_hl = 5;
            ip3->ip_tos = 0;
            ip3->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_hdr_size);
            ip3->ip_id = 0;
            ip3->ip_off = 0;
            ip3->ip_ttl = 32;
            ip3->ip_p = ip_protocol_icmp;
            ip3->ip_src = ifInfo.ip;
            ip3->ip_dst = ip->ip_src;
            ip3->ip_sum = 0;
            ip3->ip_sum = cksum(ip3, sizeof(sr_ip_hdr_t));
        
            // ICMP header
            ic3->icmp_type = 3;  // Destination Unreachable
            ic3->icmp_code = 0;  // Net Unreachable
            ic3->icmp_sum = 0;
            ic3->unused = 0;
            ic3->next_mtu = 0;
            // Copy original IP header + 8 bytes
            memcpy(ic3->data, original_ip_data.data(), origDataLen);
            ic3->icmp_sum = cksum(ic3, icmp_hdr_size);
        
            packetSender->sendPacket(resp, iface);
            return;
        }

        // We have a route (and possibly a gateway)
        auto route = *entryOpt;
        uint32_t nextHop = route.gateway ? route.gateway : ip->ip_dst;
        auto macOpt = arpCache->getEntry(nextHop);
        // In the route lookup section where we handle missing ARP entries
        if (!macOpt) {
            // Only queue the packet - ArpCache will handle sending the ARP request
            arpCache->queuePacket(nextHop, packet, iface, route.iface);
            return;
        }

        // Rewrite Ethernet addresses for forwarding.
        memcpy(eth->ether_dhost, macOpt->data(), ETHER_ADDR_LEN);
        auto outIf = routingTable->getRoutingInterface(route.iface);
        memcpy(eth->ether_shost, outIf.mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(packet, route.iface);
        return;
    }

    spdlog::error("Unsupported EtherType: 0x{:04x}", ethType);
}
