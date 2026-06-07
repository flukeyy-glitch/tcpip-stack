/*
 * tun.c - TUN device setup skeleton
 * Part 1 of a userspace TCP/IP stack
 *
 * Compile:	gcc -o tun tun.c
 * Run:		sudo ./tun
 *
 * In a second terminal, bring up the interface and test:
 *	sudo ip addr add 10.0.0.1/24 dev tun0
 *	sudo ip link set tun0 up
 *	ping 10.0.0.2	<- packets will appear in our program
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <arpa/inet.h>

/* -------------------------------------------------------
 * Ethernet header
 * EtherType values we care about:
 * 	0x0800 = IPv4
 * 	0x0806 = ARP
 * ------------------------------------------------------- */
#define ETHERTYPE_IPV4	0x0800
#define ETHERTYPE_ARP 	0x0806

struct eth_hdr {
	uint8_t		dst[6];	
	uint8_t 	src[6];
	uint16_t	ethertype;	/* stored big-endian on the wire */
} __attribute__((packed));

/* ------------------------------------------------------
 * tun_open - allocate a TUN interface and return its file descriptor
 *
 * name: desired interface name, e.g. "tun0". The kernel may assign a different name; the final name is written back into this buffer.
 *
 * Returns: fd on success, -1 on error (errno is set).
 * ------------------------------------------------------ */
int tun_open(char *name)
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
void hexdump(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (i % 16 == 0) printf("\n %04zx  ", i);
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

/* ---------------------------------------------------------------------------------------
 * mac_to_str - format a 6-byte MAC address as "aa:bb:cc:dd:ee:ff"
 * ---------------------------------------------------------------------------------------
 */
void mac_to_str(const uint8_t *mac, char *out)
{
	sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ---------------------------------------------------------------------------------------
 * handle_frame - parse and dispatch a single Ethernet frame
 *
 * In future, add ARP, IPv4, etc. handlers in later phases.
 *
 * --------------------------------------------------------------------*/
void handle_frame(const uint8_t *buf, ssize_t len)
{
  if (len < (ssize_t)sizeof(struct eth_hdr)) {
    fprintf(stderr, "[eth] frame too short (%zd bytes), dropping\n", len);
    return;
  }

  /* Overlay the Ethernet header struct onto the raw bytes.
  * Note: no copying - just reinterpreting the pointer. */
  const struct eth_hdr *eth = (const struct eth_hdr *)buf;

  char src_mac[18], dst_mac[18];
  mac_to_str(eth->src, src_mac);
  mac_to_str(eth->dst, dst_mac);

  uint16_t etype = ntohs(eth->ethertype); /* wire is big-endian */

  printf("[eth] %s -> %s ethertype=0x%04x len=%zd\n",
         src_mac, dst_mac, etype, len);

  switch (etype) {
  case ETHERTYPE_ARP:
    printf("        ^ ARP packet (TODO)\n");
    /*
    * TODO: parse ARP header, reply to who-has requests,
    * maintain ARP cache.
    */
    break;

  case ETHERTYPE_IPV4:
    printf("        ^ IPv4 packet (TODO)\n");
    /*
    * TODO: parse IPv4 header, verify checksum,
    * dispatch to ICMP/TCP handlers.
    */
    break;

  default:
    printf("        ^ unknown ethertype, dropping\n");
    break;
  }

  /* See raw bytes of every frame */
  /* hexdump(buf, len); */
}

/* ------------------------------------------------------------------------------
* main - open the TUN device and read frames in a loop
* ------------------------------------------------------------------------------- */
int main(void)
{
  char ifname[IFNAMSIZ] = "tun0";
  uint8_t buf[65536];

  int fd = tun_open(ifname);
  if (fd < 0) return 1;

  printf("[tun] waiting for frames on %s ...\n", ifname);
  printf("[tun] in another terminal, run:\n");
  printf("        sudo ip addr add 10.0.0.1/24 dev %s\n", ifname);
  printf("        sudo ip link set %s up\n", ifname);
  printf("        ping 10.0.0.2\n\n");

  /* Main read loop - each read() returns exactly one frame */
  for (;;) {
    ssize_t nread = read(fd, buf, sizeof(buf));
    if (nread < 0) {
      if (errno == EINTR) continue; /* interrupted by signal, retry */
      perror("read");
      break;
    }
    handle_frame(buf, nread);
  }

  close(fd);
  return 0;
}
