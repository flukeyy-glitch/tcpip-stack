/*
 * ip.h - IPv4 header structure and helpers
 * Reference: RFC 791
 */

#ifndef IP_H
#define IP_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/* Protocol numbers in the IPv4 header "protocol" field */
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

/* IPv4 header - 20 bytes minimum (no options) */
struct ip_hdr {
  uint8_t ver_ihl;    /* version (4) | header length in 32-bit words */
  uint8_t tos;        /* type of service (usually 0) */
  uint16_t tot_len;   /* total length including header */
  uint16_t id;        /* identification (for fragmentation) */
  uint16_t frag_off;  /* fragment offset + flags */
  uint8_t ttl;        /* time to live */
  uint8_t protocol;   /* uppler-layer protocol (ICMP=1, TCP=6) */
  uint16_t checksum;  /* header checksum */
  uint32_t src;       /* source IP (network byte order) */
  uint32_t dst;       /* destination IP (network byte order) */
  /* options would follow here, but we assume no options (ihl == 5) */
} __attribute__((packed));

/* Extract header length in bytes from ver_ihl field */
#define IP_HDR_LEN(ip)  (((ip)->ver_ihl & 0x0f) * 4)

/*
 * ip_checksum - compute the one's complement checksum over `len` bytes.
 * Pass the header with checksum field zeroed; result goes into that field.
 */
uint16_t ip_checksum(const void *data, size_t len);

/*
 * ip_handle - called by main loop for every IPv4 frame.
 *
 * buf       - pointer to start of IPv4 header (after Ethernet header)
 * len       - bytes from buf to end of frame
 * fd        - TAP device fd (for sending replies)
 * our_mac   - our 6-byte MAC address
 * our_ip    - our IPv4 address (network byte order)
 */
void ip_handle(const uint8_t *buf, ssize_t len,
    int fd, const uint8_t *our_mac, uint32_t our_ip);

#endif /* IP_H */
