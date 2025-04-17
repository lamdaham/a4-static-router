#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>
#include <algorithm>

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

    // 1) Ethernet header present?
    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet too small for Ethernet header");
        return;
    }
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t ethtype = ntohs(eth->ether_type);

    // --- ARP Handling ---
    if (ethtype == ethertype_arp) {
        auto* arp = reinterpret_cast<sr_arp_hdr_t*>(
            packet.data() + sizeof(sr_ethernet_hdr_t));
        uint16_t op  = ntohs(arp->ar_op);
        uint32_t sip = ntohl(arp->ar_sip);
        uint32_t tip = ntohl(arp->ar_tip);

        // Interface info for this ingress iface
        auto ifInfo = routingTable->getRoutingInterface(iface);

        // (a) ARP request for our IP -> reply
        if (op == arp_op_request && tip == ifInfo.ip) {
            std::vector<uint8_t> reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            auto* reth = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
            auto* rarp = reinterpret_cast<sr_arp_hdr_t*>(
                reply.data() + sizeof(sr_ethernet_hdr_t));
            // Ethernet: dst=orig src=ours
            memcpy(reth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
            memcpy(reth->ether_shost, ifInfo.mac.data(),  ETHER_ADDR_LEN);
            reth->ether_type = htons(ethertype_arp);
            // ARP header
            rarp->ar_hrd = htons(arp_hrd_ethernet);
            rarp->ar_pro = htons(ethertype_ip);
            rarp->ar_hln = ETHER_ADDR_LEN;
            rarp->ar_pln = sizeof(uint32_t);
            rarp->ar_op  = htons(arp_op_reply);
            memcpy(rarp->ar_sha, ifInfo.mac.data(),            ETHER_ADDR_LEN);
            rarp->ar_sip = htonl(ifInfo.ip);
            memcpy(rarp->ar_tha, arp->ar_sha,                  ETHER_ADDR_LEN);
            rarp->ar_tip = arp->ar_sip;
            packetSender->sendPacket(reply, iface);
            return;
        }
        // (b) ARP reply -> learn
        if (op == arp_op_reply) {
            mac_addr mac;
            memcpy(mac.data(), arp->ar_sha, ETHER_ADDR_LEN);
            arpCache->addEntry(ntohl(arp->ar_sip), mac);
            return;
        }
        return;
    }

    // --- IP Handling ---
    if (ethtype == ethertype_ip) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            spdlog::error("Packet too small for IP header");
            return;
        }
        auto* ip = reinterpret_cast<sr_ip_hdr_t*>(
            packet.data() + sizeof(sr_ethernet_hdr_t));
        // verify checksum
        uint16_t orig = ip->ip_sum;
        ip->ip_sum = 0;
        if (cksum(ip, ip->ip_hl * 4) != orig) {
            spdlog::error("Invalid IP checksum");
            return;
        }
        ip->ip_sum = orig;

        // check if destined for us
        bool toMe = false;
        for (auto const& kv : routingTable->getRoutingInterfaces()) {
            if (ip->ip_dst == kv.second.ip) { toMe = true; break; }
        }
        if (toMe) {
            // (a) ICMP echo request?
            if (ip->ip_p == ip_protocol_icmp &&
                packet.size() >= sizeof(sr_ethernet_hdr_t) +
                                 sizeof(sr_ip_hdr_t) +
                                 sizeof(sr_icmp_hdr_t))
            {
                auto* icmp = reinterpret_cast<sr_icmp_hdr_t*>(
                    packet.data() + sizeof(sr_ethernet_hdr_t)
                                  + sizeof(sr_ip_hdr_t));
                if (icmp->icmp_type == 8 && icmp->icmp_code == 0) {
                    // swap MACs
                    mac_addr tmp;
                    memcpy(tmp.data(), eth->ether_shost, ETHER_ADDR_LEN);
                    memcpy(eth->ether_shost, eth->ether_dhost, ETHER_ADDR_LEN);
                    memcpy(eth->ether_dhost, tmp.data(),         ETHER_ADDR_LEN);
                    // swap IPs
                    std::swap(ip->ip_src, ip->ip_dst);
                    ip->ip_ttl = 64;
                    ip->ip_sum = 0;
                    ip->ip_sum = cksum(ip, ip->ip_hl * 4);
                    // ICMP echo reply
                    icmp->icmp_type = 0;
                    icmp->icmp_code = 0;
                    icmp->icmp_sum  = 0;
                    int icmp_len = ntohs(ip->ip_len) - (ip->ip_hl * 4);
                    icmp->icmp_sum = cksum(icmp, icmp_len);
                    packetSender->sendPacket(packet, iface);
                    return;
                }
            }
            // (b) TCP/UDP to us -> port unreachable
            if (ip->ip_p == ip_protocol_tcp || ip->ip_p == ip_protocol_udp) {
                // build ICMP type3 code3
                auto ifInfo = routingTable->getRoutingInterface(iface);
                size_t size = sizeof(sr_ethernet_hdr_t)
                            + sizeof(sr_ip_hdr_t)
                            + sizeof(sr_icmp_t3_hdr_t);
                std::vector<uint8_t> resp(size);
                auto* reth = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
                auto* ip2  = reinterpret_cast<sr_ip_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t));
                auto* icmp2= reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                // ETH
                memcpy(reth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
                memcpy(reth->ether_shost, ifInfo.mac.data(),   ETHER_ADDR_LEN);
                reth->ether_type = htons(ethertype_ip);
                // IP
                ip2->ip_v   = 4;
                ip2->ip_hl  = 5;
                ip2->ip_tos = 0;
                ip2->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                ip2->ip_id  = 0;
                ip2->ip_off = 0;
                ip2->ip_ttl = 64;
                ip2->ip_p   = ip_protocol_icmp;
                ip2->ip_src = htonl(ifInfo.ip);
                ip2->ip_dst = ip->ip_src;
                ip2->ip_sum = 0;
                ip2->ip_sum = cksum(ip2, sizeof(sr_ip_hdr_t));
                // ICMP type3
                icmp2->icmp_type = 3;
                icmp2->icmp_code = 3;
                icmp2->icmp_sum  = 0;
                icmp2->unused    = 0;
                icmp2->next_mtu  = 0;
                size_t datalen = std::min<size_t>(ICMP_DATA_SIZE,
                                    ip->ip_hl*4 + 8);
                memcpy(icmp2->data, ip, datalen);
                icmp2->icmp_sum = cksum(icmp2, sizeof(sr_icmp_t3_hdr_t));
                packetSender->sendPacket(resp, iface);
                return;
            }
            return;
        }
        // decrement TTL
        if (--ip->ip_ttl == 0) {
            // ICMP Time Exceeded (type11 code0)
            auto ifInfo = routingTable->getRoutingInterface(iface);
            size_t size = sizeof(sr_ethernet_hdr_t)
                        + sizeof(sr_ip_hdr_t)
                        + sizeof(sr_icmp_t3_hdr_t);
            std::vector<uint8_t> resp(size);
            auto* reth = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
            auto* ip2  = reinterpret_cast<sr_ip_hdr_t*>(resp.data()+sizeof(sr_ethernet_hdr_t));
            auto* icmp2= reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
            // ETH
            memcpy(reth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
            memcpy(reth->ether_shost, ifInfo.mac.data(),   ETHER_ADDR_LEN);
            reth->ether_type = htons(ethertype_ip);
            // IP
            ip2->ip_v   = 4;
            ip2->ip_hl  = 5;
            ip2->ip_tos = 0;
            ip2->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            ip2->ip_id  = 0;
            ip2->ip_off = 0;
            ip2->ip_ttl = 64;
            ip2->ip_p   = ip_protocol_icmp;
            ip2->ip_src = htonl(ifInfo.ip);
            ip2->ip_dst = ip->ip_src;
            ip2->ip_sum = 0;
            ip2->ip_sum = cksum(ip2, sizeof(sr_ip_hdr_t));
            // ICMP type11
            icmp2->icmp_type = 11;
            icmp2->icmp_code = 0;
            icmp2->icmp_sum  = 0;
            icmp2->unused    = 0;
            icmp2->next_mtu  = 0;
            size_t datalen2 = std::min<size_t>(ICMP_DATA_SIZE,
                                  ip->ip_hl*4 + 8);
            memcpy(icmp2->data, ip, datalen2);
            icmp2->icmp_sum = cksum(icmp2, sizeof(sr_icmp_t3_hdr_t));
            packetSender->sendPacket(resp, iface);
            return;
        }
        ip->ip_sum = 0;
        ip->ip_sum = cksum(ip, ip->ip_hl * 4);
        // routing lookup
        auto entryOpt = routingTable->getRoutingEntry(ip->ip_dst);
        if (!entryOpt) {
            // Destination network unreachable (type3 code0)
            auto ifInfo = routingTable->getRoutingInterface(iface);
            size_t size = sizeof(sr_ethernet_hdr_t)
                        + sizeof(sr_ip_hdr_t)
                        + sizeof(sr_icmp_t3_hdr_t);
            std::vector<uint8_t> resp(size);
            auto* reth = reinterpret_cast<sr_ethernet_hdr_t*>(resp.data());
            auto* ip2  = reinterpret_cast<sr_ip_hdr_t*>(resp.data()+sizeof(sr_ethernet_hdr_t));
            auto* icmp2= reinterpret_cast<sr_icmp_t3_hdr_t*>(resp.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
            memcpy(reth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
            memcpy(reth->ether_shost, ifInfo.mac.data(),   ETHER_ADDR_LEN);
            reth->ether_type = htons(ethertype_ip);
            ip2->ip_v   = 4; ip2->ip_hl = 5; ip2->ip_tos=0;
            ip2->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
            ip2->ip_id  = 0; ip2->ip_off=0; ip2->ip_ttl=64;
            ip2->ip_p   = ip_protocol_icmp;
            ip2->ip_src = htonl(ifInfo.ip);
            ip2->ip_dst = ip->ip_src;
            ip2->ip_sum=0; ip2->ip_sum = cksum(ip2, sizeof(sr_ip_hdr_t));
            icmp2->icmp_type=3; icmp2->icmp_code=0;
            icmp2->icmp_sum=0; icmp2->unused=0; icmp2->next_mtu=0;
            size_t datalen3 = std::min<size_t>(ICMP_DATA_SIZE,
                                  ip->ip_hl*4 + 8);
            memcpy(icmp2->data, ip, datalen3);
            icmp2->icmp_sum = cksum(icmp2, sizeof(sr_icmp_t3_hdr_t));
            packetSender->sendPacket(resp, iface);
            return;
        }
        auto entry = *entryOpt;
        uint32_t nextHop = entry.gateway ? entry.gateway : ip->ip_dst;
        auto macOpt = arpCache->getEntry(nextHop);
        if (!macOpt) {
            arpCache->queuePacket(nextHop, packet, entry.iface);
            return;
        }
        auto nh_mac = *macOpt;
        memcpy(eth->ether_dhost, nh_mac.data(), ETHER_ADDR_LEN);
        auto outIf = routingTable->getRoutingInterface(entry.iface);
        memcpy(eth->ether_shost, outIf.mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(packet, entry.iface);
        spdlog::info("Forwarded packet via {}", entry.iface);
        return;
    }
    spdlog::error("Unsupported EtherType: 0x{:04x}", ethtype);
}
