/*
 * main.c - TUN device setup + main frame dispatch loop
 * Latest feat: wiring in ARP handler
 *
 * Compile:	gcc -o stack main.c arp.c
 * Run:		sudo ./stack
 *
 * In a second terminal:
 *	sudo ip addr add 10.0.0.1/24 dev tun0
 *	sudo ip link set tun0 up
 *	ping 10.0.0.2	<- packets will appear in our program
*/

#include <iso646.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <arpa/inet.h>

#include "arp.h"

/* ----------------------------------------------------------------------
 * Our stack's identity on the network.
 * 10.0.0.2 = the IP we claim to be (the host you're pinging).
 * The MAC is made up
 * ---------------------------------------------------------------------- */
static const uint8_t OUR_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static uint32_t      OUR_IP;    /* set from OUR_IP_STR at startup */
#define OUR_IP_STR "10.0.0.2"

/* ------------------------------------------------------
 * tun_open - allocate a TUN interface and return its file descriptor
 *
 * name: desired interface name, e.g. "tun0". The kernel may assign a different name; the final name is written back into this buffer.
 *
 * Returns: fd on success, -1 on error (errno is set).
 * ------------------------------------------------------ */
static int tun_open(char *name)
{
	struct ifreq ifr;
	int fd;

	/* 1. Open the clone device */
	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open /dev/net/tun");
		return -1;
	}

	/* 2. Configure: TUN mode (layer 3) vs TAP mode (layer 2)
	 *
	 * 	IFF_TUN - IP packets, no Ethernet header
	 * 	IFF_TAP - Ethernet frames including MAC header
	 * 	IFF_NO_PI - don't prepend a 4-byte packet info header
	 *
	 * We use IFF_TAP so we can implement ARP and see Ethernet frames.
	 */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (*name) {
		/* Request a specific name; kernel uses it if available */
		strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	}

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		perror("ioctl TUNSETIFF");
		close(fd);
		return -1;
	}

	/* Write the actual interface name back to the caller */
	strncpy(name, ifr.ifr_name, IFNAMSIZ);

	printf("[tun] opened interface: %s (fd=%d)\n", name, fd);
	return fd;
}

/* ---------------------------------------------------------------------------
 * hexdump - print len bytes of buf as a hex dump (useful for debugging)
 *
 * --------------------------------------------------------------------------- */
static void hexdump(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (i % 16 == 0) printf("\n %04zx  ", i);
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

/* ---------------------------------------------------------------------------------------
 * handle_frame - parse and dispatch a single Ethernet frame to protocol handler
 * --------------------------------------------------------------------*/
static void handle_frame(int fd, const uint8_t *buf, ssize_t len)
{
  if (len < (ssize_t)sizeof(struct eth_hdr)) {
    fprintf(stderr, "[eth] frame too short (%zd bytes), dropping\n", len);
    return;
  }

  /* Overlay the Ethernet header struct onto the raw bytes.
  * Note: no copying - just reinterpreting the pointer. */
  const struct eth_hdr *eth = (const struct eth_hdr *)buf;

  uint16_t etype = ntohs(eth->ethertype); /* wire is big-endian */

  /* Payload starts immediately after the 14-byte Ethernet header */
  const uint8_t *payload = buf + sizeof(struct eth_hdr);
  ssize_t        plen    = len - sizeof(struct eth_hdr);

  switch (etype) {
  case ETHERTYPE_ARP:
    arp_handle(payload, plen, fd, OUR_MAC, OUR_IP);
    break;

  case ETHERTYPE_IPV4:
    /*
     * TODO: parse IPv4 header, dispatch to ICMP / TCP.
     * For now just notes that we're receiving IP packets
     */
    printf("[ip]  IPv4 packet received (len=%zd) — TODO phase 3\n", len);
    /* hexdump(payload, plen); */
    break;

  case 0x86DD:
    /* IPv6 - ignore for this implementation */
    break;

  default:
    printf("[eth] unknown ethertype 0x%04x, dropping\n", etype);
    break;
  }
}

/* ------------------------------------------------------------------------------
* main - open the TUN device and read frames in a loop
* ------------------------------------------------------------------------------- */
int main(void)
{
  /* Parse our IP address into network byte order */
  if (inet_pton(AF_INET, OUR_IP_STR, &OUR_IP) != 1) {
    fprintf(stderr, "invalid IP: %s\n", OUR_IP_STR);
    return 1;
  }

  char ifname[IFNAMSIZ] = "tun0";
  uint8_t buf[65536];

  int fd = tun_open(ifname);
  if (fd < 0) return 1;

  printf("[stack] our IP:   %s\n", OUR_IP_STR);
  printf("[stack] our MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         OUR_MAC[0], OUR_MAC[1], OUR_MAC[2],
         OUR_MAC[3], OUR_MAC[4], OUR_MAC[5]);
  printf("\n[stack] in another terminal, run:\n");
  printf("        sudo ip addr add 10.0.0.1/24 dev %s\n", ifname);
  printf("        sudo ip link set %s up\n", ifname);
  printf("        ping %s\n\n", OUR_IP_STR);

  /* Main read loop - each read() returns exactly one frame */
  for (;;) {
    ssize_t nread = read(fd, buf, sizeof(buf));
    if (nread < 0) {
      if (errno == EINTR) continue; /* interrupted by signal, retry */
      perror("read");
      break;
    }
    handle_frame(fd, buf, nread);
  }

  close(fd);
  return 0;
}
