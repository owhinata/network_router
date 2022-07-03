cmake_minimum_required(VERSION 3.13)
project(packet_capture CXX)
add_executable(pcap
  src/pcap.cpp
  src/analyze.cpp
  src/checksum.cpp)
