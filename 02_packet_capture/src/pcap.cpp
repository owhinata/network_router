
#include <arpa/inet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "analyze.h"

int PrintEtherHeader(struct ether_header* eh, FILE* fp);

int InitRawSocket(const char* device, int promisc_flag, int ip_only) {
  struct ifreq ifreq;
  struct sockaddr_ll sa;
  int soc;

  const uint16_t protocol = htons(ip_only ? ETH_P_IP : ETH_P_ALL);

  if ((soc = socket(PF_PACKET, SOCK_RAW, protocol)) < 0) {
    perror("socket");
    return -1;
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
    perror("ioctl");
    close(soc);
    return -1;
  }

  sa.sll_family = PF_PACKET;
  sa.sll_protocol = protocol;
  sa.sll_ifindex = ifreq.ifr_ifindex;

  if (bind(soc, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(soc);
    return -1;
  }

  if (promisc_flag) {
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return -1;
    }
    ifreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
      perror("ioctl");
      close(soc);
      return -1;
    }
  }

  return soc;
}

int main(int argc, char* argv[]) {
  int soc, size;
  uint8_t buf[65535];

  if (argc < 2) {
    fprintf(stderr, "pcap device-name\n");
    return 1;
  }

  if ((soc = InitRawSocket(argv[1], 0, 0)) == -1) {
    fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
    return 1;
  }

  while (1) {
    if ((size = read(soc, buf, sizeof(buf))) <= 0) {
      perror("read");
    } else {
      AnalyzePacket(buf, size);
    }
  }

  close(soc);
}
