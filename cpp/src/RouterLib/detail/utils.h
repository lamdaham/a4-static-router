#ifndef UTILS_RAW_H
#define UTILS_RAW_H

#include <stdint.h>
#include <netinet/in.h>

#include "RouterTypes.h"

uint16_t cksum(const void *_data, int len);
mac_addr make_mac_addr(void* addr);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);
std::string ip_to_str(uint32_t ip);
std::string mac_to_str(const mac_addr& mac);

#endif //UTILS_RAW_H
