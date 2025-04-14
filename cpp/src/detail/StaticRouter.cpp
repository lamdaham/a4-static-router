#include "StaticRouter.h"
#include "protocol.h"   // Assumed to define: sr_ethernet_hdr, sr_ip_hdr, sr_arp_hdr, icmp_hdr, etc.
#include <cstring>
#include <arpa/inet.h>

// ----------------------------------------------------------------
// Constructor: store pointers and create an ARP cache.
StaticRouter::StaticRouter(std::shared_ptr<IRoutingTable> rt,
                           std::shared_ptr<IPacketSender> sender,
                           std::chrono::seconds arpCacheTimeout,
                           std::chrono::milliseconds arpResendInterval,
                           std::chrono::seconds arpRequestTimeout)
    : routingTable(rt), packetSender(sender),
      resendInterval(arpResendInterval), requestTimeout(arpRequestTimeout)
{
    arpCache = createArpCache(arpCacheTimeout);
}

// ----------------------------------------------------------------
// Main packet handler.
void StaticRouter::handlePacket(const std::vector<uint8_t>& packet, const std::string& inInterface) {
    // Check that packet is long enough for an Ethernet header.
    if (packet.size() < sizeof(sr_ethernet_hdr)) return;

    const sr_ethernet_hdr* ethHdr = reinterpret_cast<const sr_ethernet_hdr*>(packet.data());
    uint16_t etherType = ntohs(ethHdr->ether_type);
    if (etherType == ethertype_arp) {
        processArpPacket(packet, inInterface);
    } else if (etherType == ethertype_ip) {
        processIpPacket(packet, inInterface);
    }
    // Otherwise, unsupported payload type; drop the packet.
}

// ----------------------------------------------------------------
// Process ARP packets.
void StaticRouter::processArpPacket(const std::vector<uint8_t>& packet, const std::string& inInterface) {
    if (packet.size() < sizeof(sr_ethernet_hdr) + sizeof(sr_arp_hdr))
        return;
    const sr_arp_hdr* arpHdr = reinterpret_cast<const sr_arp_hdr*>(packet.data() + sizeof(sr_ethernet_hdr));
    uint16_t op = ntohs(arpHdr->arp_op);

    if (op == arp_op_request) {
         // If the target IP of the ARP request matches the IP of the interface
         // (you can query this via routingTable->getInterfaceIP(inInterface)),
         // then build an ARP reply. [Your code here: check ip equality.]
         // Construct a reply message setting arp_op to arp_op_reply and swapping MAC addresses.
    } else if (op == arp_op_reply) {
         // For ARP replies, update the ARP cache.
         arpCache->insert(arpHdr->arp_sip,
                          std::vector<uint8_t>(arpHdr->arp_sha, arpHdr->arp_sha + 6));
    }
}

// ----------------------------------------------------------------
// Process IP packets.
void StaticRouter::processIpPacket(const std::vector<uint8_t>& packet, const std::string& inInterface) {
    if (packet.size() < sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr))
        return;
    const sr_ip_hdr* ipHdr = reinterpret_cast<const sr_ip_hdr*>(packet.data() + sizeof(sr_ethernet_hdr));

    // Validate the IP checksum (assume ip_checksum returns 0 if valid).
    if (ip_checksum(ipHdr, (ipHdr->ip_vhl & 0x0F) * 4) != 0)
         return;  // Invalid checksum; drop.

    uint32_t dstIP = ipHdr->ip_dst;
    if (routingTable->isLocalAddress(dstIP)) {
         // If the destination IP belongs to one of our interfaces.
         if (ipHdr->ip_p == ip_protocol_icmp) {
             sendIcmpEchoReply(packet, inInterface);
         } else if (ipHdr->ip_p == ip_protocol_tcp || ipHdr->ip_p == ip_protocol_udp) {
             sendIcmpError(3, 3, packet, inInterface);  // Port unreachable.
         }
         return;
    }

    // Forwarding:
    sr_ip_hdr modifiedIp = *ipHdr;  // Copy header.
    if (modifiedIp.ip_ttl <= 1) {
         sendIcmpError(11, 0, packet, inInterface); // Time Exceeded.
         return;
    }
    modifiedIp.ip_ttl--;
    modifiedIp.ip_sum = 0;
    modifiedIp.ip_sum = ip_checksum(&modifiedIp, (modifiedIp.ip_vhl & 0x0F) * 4);

    // Longest prefix match.
    RoutingTableEntry entry;
    if (!routingTable->lookup(dstIP, entry)) {
         sendIcmpError(3, 0, packet, inInterface);  // Destination net unreachable.
         return;
    }

    uint32_t nextHopIP = (entry.next_hop != 0) ? entry.next_hop : dstIP;

    // Check ARP cache for next-hop MAC address.
    std::vector<uint8_t> nextHopMac;
    if (arpCache->lookup(nextHopIP, nextHopMac)) {
         std::vector<uint8_t> forwardPacket = packet;
         sr_ethernet_hdr* fEthHdr = reinterpret_cast<sr_ethernet_hdr*>(forwardPacket.data());
         std::copy(nextHopMac.begin(), nextHopMac.end(), fEthHdr->ether_dhost);
         std::vector<uint8_t> outgoingMac = routingTable->getInterfaceMac(entry.interface);
         std::copy(outgoingMac.begin(), outgoingMac.end(), fEthHdr->ether_shost);

         // Update IP header in forwarded packet.
         sr_ip_hdr* fIpHdr = reinterpret_cast<sr_ip_hdr*>(forwardPacket.data() + sizeof(sr_ethernet_hdr));
         fIpHdr->ip_ttl = modifiedIp.ip_ttl;
         fIpHdr->ip_sum = modifiedIp.ip_sum;

         packetSender->sendPacket(forwardPacket, entry.interface);
    } else {
         // Queue the packet in the ARP cache and initiate ARP request.
         arpCache->queuePacket(nextHopIP, packet, entry.interface);
    }
}

// ----------------------------------------------------------------
// Generate an ICMP Echo Reply.
void StaticRouter::sendIcmpEchoReply(const std::vector<uint8_t>& ipPacket, const std::string& inInterface) {
    std::vector<uint8_t> replyPacket = ipPacket;
    sr_ethernet_hdr* ethHdr = reinterpret_cast<sr_ethernet_hdr*>(replyPacket.data());
    sr_ip_hdr* ipHdr = reinterpret_cast<sr_ip_hdr*>(replyPacket.data() + sizeof(sr_ethernet_hdr));

    // Swap source and destination IP addresses.
    uint32_t temp = ipHdr->ip_src;
    ipHdr->ip_src = ipHdr->ip_dst;
    ipHdr->ip_dst = temp;

    // Process the ICMP header (assume it follows immediately).
    icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>(replyPacket.data() + sizeof(sr_ethernet_hdr) +
                                                   ((ipHdr->ip_vhl & 0x0F) * 4));
    icmp->icmp_type = 0; // Echo Reply.
    icmp->icmp_sum = 0;
    int icmpLen = ntohs(ipHdr->ip_len) - ((ipHdr->ip_vhl & 0x0F) * 4);
    icmp->icmp_sum = ip_checksum(icmp, icmpLen);

    // Swap Ethernet addresses.
    uint8_t origSrc[6];
    std::copy(ethHdr->ether_shost, ethHdr->ether_shost + 6, origSrc);
    std::copy(origSrc, origSrc + 6, ethHdr->ether_dhost);
    std::vector<uint8_t> ourMac = routingTable->getInterfaceMac(inInterface);
    std::copy(ourMac.begin(), ourMac.end(), ethHdr->ether_shost);

    packetSender->sendPacket(replyPacket, inInterface);
}

// ----------------------------------------------------------------
// Generate an ICMP error message.
void StaticRouter::sendIcmpError(uint8_t type, uint8_t code,
                                 const std::vector<uint8_t>& originalPacket,
                                 const std::string& inInterface) {
    // Construct a new packet: Ethernet header + IP header + ICMP header + portion of original IP header and 8 bytes.
    size_t totalLen = sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + sizeof(icmp_hdr) + sizeof(sr_ip_hdr) + 8;
    std::vector<uint8_t> errPacket(totalLen, 0);

    // Fill Ethernet header.
    sr_ethernet_hdr* ethHdr = reinterpret_cast<sr_ethernet_hdr*>(errPacket.data());
    const sr_ethernet_hdr* origEth = reinterpret_cast<const sr_ethernet_hdr*>(originalPacket.data());
    std::vector<uint8_t> ourMac = routingTable->getInterfaceMac(inInterface);
    std::copy(ourMac.begin(), ourMac.end(), ethHdr->ether_shost);
    std::copy(origEth->ether_shost, origEth->ether_shost + 6, ethHdr->ether_dhost);
    ethHdr->ether_type = htons(ethertype_ip);

    // Fill IP header.
    sr_ip_hdr* ipHdr = reinterpret_cast<sr_ip_hdr*>(errPacket.data() + sizeof(sr_ethernet_hdr));
    ipHdr->ip_vhl = 0x45;
    ipHdr->ip_tos = 0;
    ipHdr->ip_len = htons(totalLen - sizeof(sr_ethernet_hdr));
    ipHdr->ip_id = 0;
    ipHdr->ip_off = 0;
    ipHdr->ip_ttl = 64;
    ipHdr->ip_p = ip_protocol_icmp;
    ipHdr->ip_src = routingTable->getInterfaceIP(inInterface);
    const sr_ip_hdr* origIp = reinterpret_cast<const sr_ip_hdr*>(originalPacket.data() + sizeof(sr_ethernet_hdr));
    ipHdr->ip_dst = origIp->ip_src;
    ipHdr->ip_sum = 0;
    ipHdr->ip_sum = ip_checksum(ipHdr, sizeof(sr_ip_hdr));

    // Fill ICMP header.
    icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>(errPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr));
    icmp->icmp_type = type;
    icmp->icmp_code = code;
    icmp->icmp_sum = 0;
    // Copy original IP header + first 8 bytes of data.
    uint8_t* icmpData = icmp->data;
    const uint8_t* origIpBytes = reinterpret_cast<const uint8_t*>(origIp);
    size_t copyLen = sizeof(sr_ip_hdr) + 8;
    std::copy(origIpBytes, origIpBytes + copyLen, icmpData);
    int icmpTotalLen = sizeof(icmp_hdr) + copyLen;
    icmp->icmp_sum = ip_checksum(icmp, icmpTotalLen);

    packetSender->sendPacket(errPacket, inInterface);
}
