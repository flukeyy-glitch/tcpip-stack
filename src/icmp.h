/*
 * icmp.h - ICMP types, structures, and function declarations
 * Reference: RFC 792
 */

#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <unistd.h>
#include "ip.h"

/* ICMP message types we care about */
#define ICMP_TYPE_ECHO_REQUEST  8
#define ICMP_TYPE_ECHO_REPLY    0

/* ICMP header - 8 bytes, followed by variable-length data */
struct icmp_hdr {
  uint8_t type;       /* message type (8 = echo request, 0 = echo reply) */
  uint8_t code;       /* subtype - always 0 for each request/reply */
  uint16_t checksum;  /* checksum over entire ICMP message */
  uint16_t id;        /* identifier - echoed back in reply */
  uint16_t seq;       /* sequence number - echoed back in reply */
  /* payload (the ping data) follows immediately */
} __attribute__((packed));

/*
 * icmp_handle - process an ICMP message and send a reply if needed.
 *
 * buf         - pointer to start of ICMP header (after IP header)
 * len         - bytes remaining (ICMP header + payload)
 * fd          - TAP device fd
 * our_mac     - our MAC address
 * our_ip      - our IPv4 address (network byte order)
 * ip          - pointer to the IPv4 header of the enclosing packet
 *               (needed to build the reply's IP header and Ethernet frame)
 * src_mac     - sender's MAC address (from the Ethernet header)
 */
void icmp_handle(const uint8_t *buf, ssize_t len,
    int fd,
    const uint8_t *our_mac, uint32_t our_ip,
    const struct ip_hdr *ip, const uint8_t *src_mac);

#endif /* ICMP_H */
