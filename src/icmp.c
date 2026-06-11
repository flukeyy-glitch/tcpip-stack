/*
* icmp.c - ICMP echo request/reply implementation
* Reference: RFC 792
*/

#include "icmp.h"
#include "ip.h"
#include "arp.h"  /* eth_hdr, ETHERTYPE_IPV4 */

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
* icmp_handle - parse an ICMP message and reply to echo requests
* --------------------------------------------------------------------------
*/
void icmp_handle(const uint8_t *buf, ssize_t len,
                 int fd,
                 const uint8_t *our_mac, uint32_t our_ip,
                 const struct ip_hdr *req_ip, const uint8_t *src_mac)
{
  if (len < (ssize_t)sizeof(struct icmp_hdr)) {
    fprintf(stderr, "[icmp] message too short, dropping\n");
    return;
  }

  const struct icmp_hdr *icmp = (const struct icmp_hdr*)buf;

/* Skip rx checksum verification (TAP offloading) */

  switch (icmp->type) {

  case ICMP_TYPE_ECHO_REQUEST: {
      printf("[icmp] echo request id=%d seq=%d - sending reply\n",
             ntohs(icmp->id), ntohs(icmp->seq));

      /*
      * Build the reply packet:
      *
      *   [ Ethernet (14) ][ IPv4 (20) ][ ICMP header (8) ][ payload ]
      *
      * We copy the entire ICMP message (header + payload) from the
      * request and just change the type field and recompute the checksum.
      */
      size_t  icmp_len  = len;    /* same size as request */
      size_t  ip_len    = sizeof(struct ip_hdr) + icmp_len;
      size_t  frame_len = sizeof(struct eth_hdr) + ip_len;

      uint8_t *pkt = calloc(1, frame_len);
      if (!pkt) { perror("calloc"); return; }

      /* ---- Ethernet header ---- */
      struct eth_hdr *eth = (struct eth_hdr *)pkt;
      memcpy(eth->dst, src_mac, 6);   /* reply goes back to sender */
      memcpy(eth->src, our_mac, 6);
      eth->ethertype = htons(ETHERTYPE_IPV4);

      /* ---- IPv4 header ---- */
      struct ip_hdr *ip = (struct ip_hdr *)(pkt + sizeof(struct eth_hdr));
      ip->ver_ihl  = 0x45;         /* version=4, header_len=5*4=20 */
      ip->tos      = 0;
      ip->tot_len  = htons(ip_len);
      ip->id       = req_ip->id;   /* echo back the same ID */
      ip->frag_off = htons(0x4000); /* don't fragment bit set */
      ip->ttl      = 64;
      ip->protocol = IP_PROTO_ICMP;
      ip->checksum = 0;   /* zero before computing */
      ip->src      = our_ip;
      ip->dst      = req_ip->src;   /* send back to whoever asked */

      ip->checksum = ip_checksum(ip, sizeof(struct ip_hdr));

      /* ---- ICMP message (copy request, change type) ---- */
      uint8_t *icmp_out = pkt + sizeof(struct eth_hdr) + sizeof(struct ip_hdr);
      memcpy(icmp_out, buf, icmp_len);  /* copy header + payload verbatim */

      struct icmp_hdr *reply = (struct icmp_hdr *)icmp_out;
      reply->type     = ICMP_TYPE_ECHO_REPLY;
      reply->code     = 0;
      reply->checksum = 0;  /* zero before computing */
      reply->checksum = ip_checksum(icmp_out, icmp_len);

      /* ---- Send it ---- */
      ssize_t written = write(fd, pkt, frame_len);
      if (written < 0) {
        perror("[icmp] write failed");
      } else {
        printf("[icmp] echo reply sent (%zd bytes)\n", written);
      }

      free(pkt);
      break;
    }

    case ICMP_TYPE_ECHO_REPLY:
    /* We sent a ping and got a reply - not needed yet but good to log */
    printf("[icmp] echo reply received id=%d seq=%d\n",
           ntohs(icmp->id), ntohs(icmp->seq));
    break;

    default:
    printf("[icmp] unhandled type=%d code=%d, dropping\n",
           icmp->type, icmp->code);
    break;
  }
}
