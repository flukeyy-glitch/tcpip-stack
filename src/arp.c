/*
* arp.c - ARP (Address Resolution Protocol) implementation
* 
* Handles:
*   - Parsing incoming ARP packets
*   - Replying to ARP requests (who-has -> is-at)
*   - Maintaining a simple ARP cache (IP -> MAC)
*
* Reference: RFC 826
*/

#include "arp.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>  /* htons, ntohs, htonl, ntohl */

/* ----------------------------------------------------------------
* ARP cache - a fixed-size table mapping IPv4 -> MAC
* In a real stack you'd use a hash map and add expiry timers.
* ----------------------------------------------------------------- */
#define ARP_CACHE_SIZE 64

typedef struct {
  uint32_t ip;
  uint8_t  mac[6];
  int      valid;
} arp_entry_t;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];

/* ----------------------------------------------------------------- 
* arp_cache_update - insert or update an entry in the ARP cache
* Called any time we see an ARP packet (request or reply) so we learn
* the sender's mapping for free.
* ------------------------------------------------------------------ */
static void arp_cache_update(uint32_t ip, const uint8_t *mac)
{
  /* Look for an existing entry first */
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip) {
      memcpy(arp_cache[i].mac, mac, 6);
      return;
    }
  }

  /* Find a free slot */
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (!arp_cache[i].valid) {
      arp_cache[i].ip    = ip;
      arp_cache[i].valid = 1;
      memcpy(arp_cache[i].mac, mac, 6);

      char ipstr[16];
      struct in_addr a = { .s_addr = ip };
      inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));

      printf("[arp] cache: learned %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
             ipstr,
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      return;
    }
  }

  fprintf(stderr, "[arp] cache full, dropping entry\n");
}

/* ---------------------------------------------------------------------
* arp_cache_lookup - find a MAC for a given IP
* Returns 0 on success (mac filled in), -1 if not found.
* ---------------------------------------------------------------------- */
int arp_cache_lookup(uint32_t ip, uint8_t *mac_out)
{
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip) {
      memcpy(mac_out, arp_cache[i].mac, 6);
      return 0;
    }
  }
  return -1;
}

/* ---------------------------------------------------------------------- 
* arp_send_reply - craft and send an ARP reply
*
* We received: who has <target_ip>? tell <sender_ip>
* We reply:    <target_ip> is at <our_mac>
*
* fd:        the TAP device file descriptor to write to
* our_mac:   our MAC address (6 bytes)
* our_ip:    our IPv4 address (network byte order)
* their_mac: requester's MAC address (we send reply directly to them)
* their_ip:  requester's IPv4 address
* ----------------------------------------------------------------------- */
static void arp_send_reply(int fd,
                           const uint8_t *our_mac,   uint32_t our_ip,
                           const uint8_t *their_mac, uint32_t their_ip)
{
  /*
  * Layout of the packet we send:
  *
  *   [ Ethernet header (14 bytes) ][ ARP header (28 bytes) ]
  *
  * Total: 42 bytes - matches len=42
  */
  uint8_t pkt[sizeof(struct eth_hdr) + sizeof(struct arp_hdr)];
  memset(pkt, 0, sizeof(pkt));

  /* --- Ethernet header --- */
  struct eth_hdr *eth = (struct eth_hdr *)pkt;
  memcpy(eth->dst, their_mac, 6);   /* send directly to requester */
  memcpy(eth->src, our_mac,   6);
  eth->ethertype = htons(ETHERTYPE_ARP);

  /* --- ARP header --- */
  struct arp_hdr *arp = (struct arp_hdr *)(pkt + sizeof(struct eth_hdr));
  arp->htype = htons(ARP_HTYPE_ETHERNET);
  arp->ptype = htons(ARP_PTYPE_IPV4);
  arp->hlen  = 6;   /* MAC address length */
  arp->plen  = 4;   /* IPv4 address length */
  arp->oper  = htons(ARP_OPER_REPLY);

  memcpy(arp->sha, our_mac, 6);   /* sender hardware address = us */
  arp->spa = our_ip;              /* sender protocol address = our IP */
  memcpy(arp->tha, their_mac, 6); /* target hardware address = them */
  arp->tpa = their_ip;            /* target protocol address = their IP */

  ssize_t written = write(fd, pkt, sizeof(pkt));
  if (written < 0) {
    perror("[arp] write reply failed");
  } else {
    char our_ipstr[16], their_ipstr[16];
    struct in_addr a = { .s_addr = our_ip };
    struct in_addr b = { .s_addr = their_ip };
    inet_ntop(AF_INET, &a, our_ipstr, sizeof(our_ipstr));
    inet_ntop(AF_INET, &b, their_ipstr, sizeof(their_ipstr));
    printf("[arp] reply: %s is at %02x:%02x:%02x:%02x:%02x:%02x (to %s)\n",
           our_ipstr,
           our_mac[0], our_mac[1], our_mac[2],
           our_mac[3], our_mac[4], our_mac[5],
           their_ipstr);
  }
}

/* --------------------------------------------------------------------------
* arp_handle - parse an ARP packet and react
*
* buf:     pointer to start of ARP header (i.e. after the Ethernet header)
* len:     remaining bytes from buf ownards
* fd:      TAP device fd (needed to send the reply)
* our_mac: our MAC address
* our_ip:  our IPv4 address (network byte order)
* --------------------------------------------------------------------------- */
void arp_handle(const uint8_t *buf, ssize_t len,
                int fd, const uint8_t *our_mac, uint32_t our_ip)
{
  if (len < (ssize_t)sizeof(struct arp_hdr)) {
    fprintf(stderr, "[arp packet too short, dropping\n");
    return;
  }

  const struct arp_hdr *arp = (const struct arp_hdr *)buf;

  /* Sanity checks - we only handle Ethernet + IPv4 ARP */
  if (ntohs(arp->htype) != ARP_HTYPE_ETHERNET) {
    printf("[arp] unsupported hardware type 0x%04x, dropping\n",
           ntohs(arp->htype));
    return;
  }
  if (ntohs(arp->ptype) != ARP_PTYPE_IPV4) {
    printf("[arp] unsupported protocol type 0x%04x, dropping\n",
           ntohs(arp->ptype));
    return;
  }

  uint16_t oper = ntohs(arp->oper);

  /* Always learn the sender's mapping - free information */
  arp_cache_update(arp->spa, arp->sha);

  switch (oper) {

    case ARP_OPER_REQUEST:
    /*
    * Someone is asking: "who has <tpa>? tell <spa>"
    * If they're asking for our IP, reply with our MAC.
    */
    if (arp->tpa == our_ip) {
        printf("[arp] request: who has our IP? replying\n");
        arp_send_reply(fd, our_mac, our_ip, arp->sha, arp->spa);
    } else {
        char ipstr[16];
        struct in_addr a = { .s_addr = arp->tpa };
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
        printf("[arp] request for %s (not us), ignoring\n", ipstr);
      }
    break;

    case ARP_OPER_REPLY:
    /*
    * Someone is telling us their MAC. We've already cached it above.
    * Nothing else to do unless you're implementing ARP request sending
    * (needed for TCP)
    */
    printf("[arp] reply received, cache updated\n");
    break;

    default:
    printf("[arp] unknown operation %d, dropping\n", oper);
    break;
  }
}
