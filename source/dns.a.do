#!/bin/sh -e
objects="dns_dfd.o dns_domain.o dns_dtda.o dns_ip.o dns_ipq.o dns_mx.o dns_name.o dns_namex.o dns_nd.o dns_packet.o dns_random.o dns_rcip.o dns_rcrw.o dns_resolve.o dns_sortip.o dns_transmit.o dns_txt.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
