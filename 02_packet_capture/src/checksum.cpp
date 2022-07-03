
#include <arpa/inet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

uint16_t Checksum(const uint8_t* data, int len) {
  register uint32_t sum = 0;
  register const uint16_t* ptr = (const uint16_t*)data;
  register int c;

  for (c = len; c > 1; c -= 2) {
    sum += *ptr;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ++ptr;
  }
  if (c == 1) {
    uint16_t val = 0;
    memcpy(&val, ptr, sizeof(uint8_t));
    sum += val;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum;
}

uint16_t Checksum2(const uint8_t* data1, int len1, const uint8_t* data2,
                   int len2) {
  register uint32_t sum = 0;
  register const uint16_t* ptr = (const uint16_t*)data1;
  register int c;

  for (c = len1; c > 1; c -= 2) {
    sum += *ptr;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ++ptr;
  }
  if (c == 1) {
    uint16_t val = ((*ptr) << 8) + (*data2);
    sum += val;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr = (const uint16_t*)(data2 + 1);
    --len2;
  } else {
    ptr = (const uint16_t*)data2;
  }

  for (c = len2; c > 1; c -= 2) {
    sum += *ptr;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ++ptr;
  }
  if (c == 1) {
    uint16_t val = 0;
    memcpy(&val, ptr, sizeof(uint8_t));
    sum += val;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum;
}

int CheckIpchecksum(const struct iphdr* iphdr, const uint8_t* option,
                    int optionlen) {
  unsigned short sum;

  if (optionlen != 0) {
    sum = Checksum((const uint8_t*)iphdr, sizeof(struct iphdr));
  } else {
    sum = Checksum2((const uint8_t*)iphdr, sizeof(struct iphdr), option,
                    optionlen);
  }

  return (sum == 0 || sum == 0xFFFF) ? 1 : 0;
}

struct pseudo_ip {
  struct in_addr ip_src;
  struct in_addr ip_dst;
  unsigned char dummy;
  unsigned char ip_p;
  unsigned short ip_len;
};

int CheckIPDATAchecksum(const struct iphdr* iphdr, const uint8_t* data,
                        int len) {
  struct pseudo_ip p_ip;
  unsigned short sum;

  memset(&p_ip, 0, sizeof(struct pseudo_ip));
  p_ip.ip_src.s_addr = iphdr->saddr;
  p_ip.ip_dst.s_addr = iphdr->daddr;
  p_ip.ip_p = iphdr->protocol;
  p_ip.ip_len = htons(len);

  sum = Checksum2((const uint8_t*)&p_ip, sizeof(struct pseudo_ip), data, len);

  return (sum == 0 || sum == 0xFFFF) ? 1 : 0;
}

struct pseudo_ip6_hdr {
  struct in6_addr src;
  struct in6_addr dst;
  unsigned long plen;
  unsigned short dmy1;
  unsigned char dmy2;
  unsigned char nxt;
};

int CheckIP6DATAchecksum(const struct ip6_hdr* ip, const uint8_t* data,
                         int len) {
  struct pseudo_ip6_hdr p_ip;
  unsigned short sum;

  memset(&p_ip, 0, sizeof(struct pseudo_ip6_hdr));
  ;
  memcpy(&p_ip.src, &ip->ip6_src, sizeof(struct in6_addr));
  memcpy(&p_ip.dst, &ip->ip6_dst, sizeof(struct in6_addr));
  p_ip.plen = ip->ip6_plen;
  p_ip.nxt = ip->ip6_nxt;

  sum = Checksum2((uint8_t*)&p_ip, sizeof(struct pseudo_ip6_hdr), data, len);

  return (sum == 0 || sum == 0xFFFF) ? 1 : 0;
}
