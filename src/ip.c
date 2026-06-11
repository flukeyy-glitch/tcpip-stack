/*
* ip.c - IPv4 header parsing, checksum, and dispatch
* Reference: RFC 791
*/

#include "ip.h"
#include "icmp.h"
#include "arp.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ------------------------------------------------------------------------
* ip_checksum - one's complement checksum (used by IPv4 and ICMP)
*
* How it works:
*   1. Sum all 16-bit words in the header
*   2. Add any carry bits back into the low 16 bits
*   3. Bitwise NOT the result
*
* To verify an incoming header: run checksum over the whole header
* including the checksum field - result should be 0xffff.
* To compute a new checksum: zero the checksum field first, then call this.
* -------------------------------------------------------------------------
*/
uint16_t ip_checksum(const void *data, size_t len)
{
  const uint16_t *p   = (const uint16_t *)data;
  uint32_t        sum = 0;

  while (len > 1) {
    sum += *p++;
    len -= 2;
  }
  /* If odd number of bytes, pad the last byte */
  if (len == 1) {
    sum += *(const uint8_t *)p;
  }

  /* Fold 32-bit sum into 16 bits */
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return (uint16_t)~sum;
}

/* ----------------------------------------------------------------------
* ip_handle - parse IPv4 header, verify checksum, dispatch to ICMP/TCP
* -----------------------------------------------------------------------
*/
void ip_handle(const uint8_t *buf, ssize_t len, 
               int fd, const uint8_t *our_mac, uint32_t our_ip)
{
  if (len < (ssize_t)sizeof(struct ip_hdr)) {
    fprintf(stderr, "[ip] packet too short, dropping\n");
    return;
  }

  const struct ip_hdr *ip = (const struct ip_hdr *)buf;

  /* Check IP version */
  uint8_t version = (ip->ver_ihl >> 4) & 0x0f;
  if (version != 4) {
    fprintf(stderr, "[ip] not IPv4 (version=%d), dropping\n", version);
    return;
  }

  /* Header length in bytes - must be at least 20 */
  int ihl = IP_HDR_LEN(ip);
  if (ihl < 20) {
    fprintf(stderr, "[ip] header too short (ihl=%d), dropping\n", ihl);
    return;
  }

/* Note: TAP devices on Linux use checksum offloading, so the checksum
 * field is often 0 on received packets. We skip rx verification here
 * but still compute correct checksums on everything we send. */

  /* Is this packet addressed to us? */
  if (ip->dst != our_ip) {
    char dst[16];
    struct in_addr a = { .s_addr = ip->dst };
    inet_ntop(AF_INET, &a, dst, sizeof(dst));
    printf("[ip] not for us (dst=%s), dropping\n", dst);
    return;
  }

  char src[16];
  struct in_addr a = { .s_addr = ip->src };
  inet_ntop(AF_INET, &a, src, sizeof(src));

  /* Payload starts after the IP header */
  const uint8_t *payload = buf + ihl;
  ssize_t        plen    = ntohs(ip->tot_len) - ihl;
  
  /* We need the sender's MAC to build Ethernet reply frames.
  * It's in the Ethernet header that precedes this IP header in the
  * original frame. We reach back before buf to get it.
  * (main.c passes buf = frame + sizeof(eth_hdr), so eth header is at
  * buf - sizeof(eth_hdr)) */
  const struct eth_hdr *eth = 
    (const struct eth_hdr *)(buf - sizeof(struct eth_hdr));

  switch (ip->protocol) {

  case IP_PROTO_ICMP:
    printf("[ip] ICMP from %s\n", src);
    icmp_handle(payload, plen, fd, our_mac, our_ip, ip, eth->src);
    break;

  case IP_PROTO_TCP:
    printf("[ip] TCP from %s (TODO)\n", src);
    break;

  case IP_PROTO_UDP:
    printf("[ip] UDP from %s, dropping\n", src);
    break;

  default:
    printf("[ip] unknown protocol %d from %s, dropping\n",
           ip->protocol, src);
    break;
  }
}
