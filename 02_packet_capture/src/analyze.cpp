
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

#include "checksum.h"

#ifndef ETHERTYPE_IPV6
#define EtHERTYPE_IPV6 0x86dd
#endif

namespace {

char* EtherNtoaR(const uint8_t* hwaddr, char* buf, socklen_t size) {
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1],
           hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
  return buf;
}

char* ArpIp2Str(const uint8_t* ip, char* buf, socklen_t size) {
  snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return buf;
}

char* IpIp2Str(const uint32_t ip, char* buf, socklen_t size) {
  struct in_addr* addr;
  addr = (struct in_addr*)&ip;
  inet_ntop(AF_INET, addr, buf, size);
  return buf;
}

template <typename T>
void PrintHeader(const T* hdr, FILE* fp) {}

template <>
void PrintHeader<struct ether_header>(const struct ether_header* eh, FILE* fp) {
  char buf[80];
  fprintf(fp, "ether_header----------------------------\n");
  fprintf(fp, "ether_dhost=%s\n",
          EtherNtoaR(eh->ether_dhost, buf, sizeof(buf)));
  fprintf(fp, "ether_shost=%s\n",
          EtherNtoaR(eh->ether_shost, buf, sizeof(buf)));
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
}

template <>
void PrintHeader<struct ether_arp>(const struct ether_arp* arp, FILE* fp) {
  static const char* hrd[] = {"From KA9Q: NET?ROM pseudo.",
                              "Ethenet 10/100Mbps.",
                              "Experimental Ethernet.",
                              "AX.25 Level 2.",
                              "PROnet token ring.",
                              "Chaosnet.",
                              "IEEE 802.2 Ethernet/TR/TB.",
                              "ARCnet.",
                              "APPLEtalk.",
                              "undefine",
                              "undefine",
                              "undefine",
                              "undefine",
                              "undefine",
                              "undefine",
                              "Frame Relay DLCI.",
                              "undefine",
                              "undefine",
                              "undefine",
                              "ATM.",
                              "undefine",
                              "undefine",
                              "undefine",
                              "Metricom STRIP (new IANA id)."};
  static const char* op[] = {"undefined",     "ARP request.", "ARP reply.",
                             "RARP request.", "RARP reply.",  "undefined",
                             "undefined",     "undefined",    "InARp request.",
                             "InARP reply.",  "(ATM)ARP NAK."};

  char buf[80];
  fprintf(fp, "arp-------------------------------------\n");
  fprintf(fp, "arp_hrd=%u", ntohs(arp->arp_hrd));
  if (ntohs(arp->arp_hrd) <= 23) {
    fprintf(fp, "(%s),", hrd[ntohs(arp->arp_hrd)]);
  } else {
    fprintf(fp, "(undefined),");
  }
  fprintf(fp, "arp_pro=%u", ntohs(arp->arp_pro));
  switch (ntohs(arp->arp_pro)) {
    case ETHERTYPE_IP:
      fprintf(fp, "(IP)\n");
      break;
    case ETHERTYPE_ARP:
      fprintf(fp, "(Address resolution)\n");
      break;
    case ETHERTYPE_REVARP:
      fprintf(fp, "(Reverse ARP)\n");
      break;
    case ETHERTYPE_IPV6:
      fprintf(fp, "(IPv6)\n");
      break;
    default:
      fprintf(fp, "(unknown)\n");
      break;
  }
  fprintf(fp, "arp_hln-%u,", arp->arp_hln);
  fprintf(fp, "arp_pln=%u,", arp->arp_pln);
  fprintf(fp, "arp_op=%u", ntohs(arp->arp_op));
  if (ntohs(arp->arp_op) <= 10) {
    fprintf(fp, "(%s)\n", op[ntohs(arp->arp_op)]);
  } else {
    fprintf(fp, "(undefine)\n");
  }
  fprintf(fp, "arp_sha=%s\n", EtherNtoaR(arp->arp_sha, buf, sizeof(buf)));
  fprintf(fp, "arp_spa=%s\n", ArpIp2Str(arp->arp_spa, buf, sizeof(buf)));
  fprintf(fp, "arp_tha=%s\n", EtherNtoaR(arp->arp_tha, buf, sizeof(buf)));
  fprintf(fp, "arp_tpa=%s\n", ArpIp2Str(arp->arp_tpa, buf, sizeof(buf)));
}

static const char* kProto[] = {
    "undefined", "ICMP",      "IGMP",      "undefined", "IPIP",
    "undefined", "TCP",       "undefined", "EGP",       "undefined",
    "undefined", "undefined", "PUP",       "undefined", "undefined",
    "undefined", "undefined", "UDP"};

void PrintIpHeader(const iphdr* iphdr, const uint8_t* option, int optionlen,
                   FILE* fp) {
  int i;
  char buf[80];
  fprintf(fp, "ip--------------------------------------\n");
  fprintf(fp, "version=%u,", iphdr->version);
  fprintf(fp, "ihl=%u,", iphdr->ihl);
  fprintf(fp, "tos=%x,", iphdr->tos);
  fprintf(fp, "tot_len=%u,", ntohs(iphdr->tot_len));
  fprintf(fp, "id=%u\n", ntohs(iphdr->id));
  fprintf(fp, "frag_off=%x,%u,", (ntohs(iphdr->frag_off) >> 13) & 0x07,
          ntohs(iphdr->frag_off) & 0x1FFF);
  fprintf(fp, "ttl=%u,", iphdr->ttl);
  fprintf(fp, "protocol=%u", iphdr->protocol);
  if (iphdr->protocol <= 17) {
    fprintf(fp, "(%s),", kProto[iphdr->protocol]);
  } else {
    fprintf(fp, "(undefined),");
  }
  fprintf(fp, "check=%x\n", iphdr->check);
  fprintf(fp, "saddr=%s,", IpIp2Str(iphdr->saddr, buf, sizeof(buf)));
  fprintf(fp, "daddr=%s\n", IpIp2Str(iphdr->daddr, buf, sizeof(buf)));
  if (optionlen > 0) {
    fprintf(fp, "option:");
    for (i = 0; i < optionlen; ++i) {
      fprintf(fp, "%s%02x", i ? ":" : "", option[i]);
    }
  }
}

template <>
void PrintHeader<struct ip6_hdr>(const struct ip6_hdr* ip6, FILE* fp) {
  char buf[80];
  fprintf(fp, "ip6-------------------------------------\n");
  fprintf(fp, "ip6_flow=%x,", ip6->ip6_flow);
  fprintf(fp, "ip6_plen=%d,", ntohs(ip6->ip6_plen));
  fprintf(fp, "ip6_nxt=%u", ip6->ip6_nxt);
  if (ip6->ip6_nxt <= 17) {
    fprintf(fp, "(%s),", kProto[ip6->ip6_nxt]);
  } else {
    fprintf(fp, "(undefined),");
  }
  fprintf(fp, "ip6_hlim=%d,", ip6->ip6_hlim);
  fprintf(fp, "ip6_src=%s\n",
          inet_ntop(AF_INET6, &ip6->ip6_src, buf, sizeof(buf)));
  fprintf(fp, "ip6_dst=%s\n",
          inet_ntop(AF_INET6, &ip6->ip6_dst, buf, sizeof(buf)));
}

//--
template <typename T>
int AnalyzeHeader(const uint8_t* data, int size) {
  const uint8_t* ptr;
  int lest;
  const T* hdr;

  ptr = data;
  lest = size;

  if (lest < sizeof(T)) {
    fprintf(stderr, "lest(%d) < sizeof(protocol header)\n", lest);
    return -1;
  }

  hdr = (const T*)ptr;
  ptr += sizeof(T);
  lest -= sizeof(T);

  PrintHeader(hdr, stdout);

  return 0;
}

template <>
int AnalyzeHeader<struct iphdr>(const uint8_t* data, int size) {
  const uint8_t* ptr;
  int lest;
  const struct iphdr* iphdr;
  const uint8_t* option;
  int optionlen, len;
  unsigned short sum;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct iphdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct iphdr)\n", lest);
    return -1;
  }
  iphdr = (const struct iphdr*)ptr;
  ptr += sizeof(struct iphdr);
  lest -= sizeof(struct iphdr);

  // IPv4 header has indefinitly lenght option.
  // Here, ptr advances option length.
  optionlen = iphdr->ihl * 4 - sizeof(struct iphdr);
  if (optionlen > 0) {
    if (optionlen >= 1500) {
      fprintf(stderr, "IP optionLen(%d):too big\n", optionlen);
      return -1;
    }
    option = ptr;
    ptr += optionlen;
    lest -= optionlen;
  }

  // TCP and UDP includes checksum in transporter, but ICMP doesn't.
  // ICMPv6 includes IP header to its checksum
  if (CheckIpchecksum(iphdr, option, optionlen) == 0) {
    fprintf(stderr, "bad ip checksum\n");
    return -1;
  }

  PrintIpHeader(iphdr, option, optionlen, stdout);

  if (iphdr->protocol == IPPROTO_ICMP) {
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    sum = Checksum(ptr, len);
    if (sum != 0 && sum != 0xFFFF) {
      fprintf(stderr, "bad icmp checksum\n");
      return -1;
    }
    AnalyzeHeader<struct icmp>(ptr, lest);
  } else if (iphdr->protocol == IPPROTO_TCP) {
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    if (CheckIPDATAchecksum(iphdr, ptr, len) == 0) {
      fprintf(stderr, "bad tcp checksum\n");
      return -1;
    }
    AnalyzeHeader<struct tcphdr>(ptr, lest);
  } else if (iphdr->protocol == IPPROTO_UDP) {
    const struct udphdr* udphdr = (const struct udphdr*)ptr;
    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
    if (udphdr->check != 0 && CheckIPDATAchecksum(iphdr, ptr, len) == 0) {
      fprintf(stderr, "bad udp checksum\n");
      return -1;
    }
    AnalyzeHeader<struct udphdr>(ptr, lest);
  }

  return 0;
}

template <>
int AnalyzeHeader<struct ip6_hdr>(const uint8_t* data, int size) {
  const uint8_t* ptr;
  int lest;
  const struct ip6_hdr* ip6;
  int len;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ip6_hdr)) {
    fprintf(stderr, "lest(%d) < sizeof(struct ip6_hdr)\n", lest);
    return -1;
  }
  ip6 = (const struct ip6_hdr*)ptr;
  ptr += sizeof(struct ip6_hdr);
  lest -= sizeof(struct ip6_hdr);

  PrintHeader(ip6, stdout);

  if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
    len = ntohs(ip6->ip6_plen);
    if (CheckIP6DATAchecksum(ip6, ptr, len) == 0) {
      fprintf(stderr, "bad icmp6 checksum\n");
      return -1;
    }
    AnalyzeHeader<struct icmp6_hdr>(ptr, lest);
  } else if (ip6->ip6_nxt == IPPROTO_TCP) {
    len = ntohs(ip6->ip6_plen);
    if (CheckIP6DATAchecksum(ip6, ptr, len) == 0) {
      fprintf(stderr, "bad tcp6 checksum\n");
      return -1;
    }
    AnalyzeHeader<struct tcphdr>(ptr, lest);
  } else if (ip6->ip6_nxt == IPPROTO_UDP) {
    len = ntohs(ip6->ip6_plen);
    if (CheckIP6DATAchecksum(ip6, ptr, len) == 0) {
      fprintf(stderr, "bad udp6 checksum\n");
      return -1;
    }
    AnalyzeHeader<struct udphdr>(ptr, lest);
  }

  return 0;
}

}  // namespace

int AnalyzePacket(const uint8_t* data, int size) {
  const uint8_t* ptr;
  int lest;
  const struct ether_header* eh;

  ptr = data;
  lest = size;

  if (lest < sizeof(struct ether_header)) {
    fprintf(stderr, "lest(%d) < sizeof(struct ether_header)\n", lest);
    return -1;
  }

  eh = (struct ether_header*)ptr;
  ptr + sizeof(struct ether_header);
  lest -= sizeof(struct ether_header);

  if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
    fprintf(stderr, "Packet[%dbytes]\n", size);
    PrintHeader(eh, stdout);
    AnalyzeHeader<struct ether_arp>(ptr, lest);
  } else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
    fprintf(stderr, "Packet[%dbytes]\n", size);
    PrintHeader(eh, stdout);
    AnalyzeHeader<struct iphdr>(ptr, lest);
  } else if (ntohs(eh->ether_type) == ETHERTYPE_IPV6) {
    fprintf(stderr, "Packet[%dbytes]\n", size);
    PrintHeader(eh, stdout);
    AnalyzeHeader<struct ip6_hdr>(ptr, lest);
  }

  return 0;
}
