/*
 * arp.h - ARP types, constants, and function declarations
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>   /* ssize_t, write */

/* ----------------------------------------------------------------
 * Ethernet header - duplicated here so arp.c is self-contained.
 * Move to shared eth.h when splitting files properly.
 * ---------------------------------------------------------------- */
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV4 0x0800

struct eth_hdr {
	uint8_t		dst[6];	
	uint8_t 	src[6];
	uint16_t	ethertype;	/* stored big-endian on the wire */
} __attribute__((packed));

/* -----------------------------------------------------------------
 * ARP header - RFC 826
 *
 * Immediately follows the Ethernet header.
 * For Ethernet + IPv4: hlen=6, plen=4, total header = 28 bytes.
 * ----------------------------------------------------------------- */
#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4     0x0800

#define ARP_OPER_REQUEST  1 /* who has <tpa>? tell <spa> */
#define ARP_OPER_REPLY    2 /* <tpa> is at <tha>         */

struct arp_hdr {
  uint16_t htype; /* hardware type (1 = Ethernet)        */
  uint16_t ptype; /* protocol type (0x0800 = IPv4)       */
  uint8_t  hlen;  /* hardware address length (6)         */
  uint8_t  plen;  /* protocol address length (4)         */
  uint16_t oper;  /* operation: request (1) or reply (2) */

  /* For Ethernet + IPv4 specifically: */
  uint8_t  sha[6]; /* sender hardware address (MAC)  */
  uint32_t spa;    /* sender protocol address (IPv4) */
  uint8_t  tha[6]; /* target hardware address (MAC)  */
  uint32_t tpa;    /* target protocol address (IPv4) */
} __attribute__((packed));

/* ------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------ */

/*
 * arp_handle - called by main loop when an ARP EtherType frame arrives.
 *
 * buf     - pointer to start of ARP header (after Ethernet header)
 * len     - bytes remaining in buf
 * fd      - TAP device fd (for sending replies)
 * our_mac - our 6-byte MAC adddress
 * our_ip  - our IPv4 address in network byte order
 */
void arp_handle(const uint8_t *buf, ssize_t len,
    int fd, const uint8_t *our_mac, uint32_t our_ip);

/*
 * arp_cache_lookup - find a MAC address for a given IP.
 * Returns 0 and fills mac_out on success; -1 if not in cache.
 * Used by the IPv4 / TCP layer in later phases.
 */
int arp_cache_lookup(uint32_t ip, uint8_t *mac_out);

#endif /* ARP_H */
