---
title: Improved Network Performance
icon: icon-key.svg
#subtitle: Subheading goes here
#links:
#    This is my link: http://google.com
---
OVS performs better than iptables, especially as the number of rules increases. There are numerous efforts in the OVS community to speed up packet IO and packet processing through technologies like Intel DPDK, AF_XDP sockets, hardware offloading, etc.