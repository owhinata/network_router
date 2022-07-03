
#ifndef PACKET_CAPTURE_SRC_CHECKSUM_H_
#define PACKET_CAPTURE_ARC_CHECKSUM_H_

#include <netinet/ip.h>
#include <netinet/ip6.h>

uint16_t Checksum(const uint8_t* data, int len);
uint16_t Checksum2(const uint8_t* data1, int len1, const uint8_t* data2,
                   int len2);
int CheckIpchecksum(const struct iphdr* iphdr, const uint8_t* option,
                    int optionlen);
int CheckIPDATAchecksum(const struct iphdr* iphdr, const uint8_t* data,
                        int len);
int CheckIP6DATAchecksum(const struct ip6_hdr* ip, const uint8_t* data,
                         int len);

#endif  // PACKET_CAPTURE_SRC_CHECKSUM_H_
