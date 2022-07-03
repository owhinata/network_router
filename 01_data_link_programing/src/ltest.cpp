
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

int InitRawSocket(const char* device, int promisc_flag, int ip_only);
int PrintEtherHeader(struct ether_header* eh, FILE* fp);

int main(int argc, char* argv[]) {
  int soc, size;
  uint8_t buf[2048];

  if (argc < 2) {
    fprintf(stderr, "ltest device-name\n");
    return 1;
  }

  if ((soc = InitRawSocket(argv[1], 1, 0)) == -1) {
    fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
    return 1;
  }

  while (1) {
    if ((size = read(soc, buf, sizeof(buf))) <= 0) {
      perror("read");
    } else {
      if (size >= sizeof(struct ether_header)) {
        PrintEtherHeader((struct ether_header*)buf, stdout);
      } else {
        fprintf(stderr, "read size(%d) < %d\n", size, sizeof(struct ether_header));
      }
    }
  }

  close(soc);
}

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

char* EtherNtoaR(uint8_t* hwaddr, char* buf, socklen_t size) {
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
      hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
  return buf;
}

int PrintEtherHeader(struct ether_header* eh, FILE* fp) {
  char buf[80];
  fprintf(fp, "ethre_header----------------------------\n");
  fprintf(fp, "ether_dhost=%s\n", EtherNtoaR(eh->ether_dhost, buf, sizeof(buf)));
  fprintf(fp, "ether_shost=%s\n", EtherNtoaR(eh->ether_shost, buf, sizeof(buf)));
  fprintf(fp, "ether_type=%02X\n", ntohs(eh->ether_type));
  switch (ntohs(eh->ether_type)) {
    case ETH_P_IP:
      fprintf(fp, "(IP)\n");
      break;
    case ETH_P_IPV6:
      fprintf(fp, "(IPv6)\n");
      break;
    case ETH_P_ARP:
      fprintf(fp, "(ARP)\n");
      break;
    default:
      fprintf(fp, "(unknown)\n");
      break;
  }
  return 0;
}

