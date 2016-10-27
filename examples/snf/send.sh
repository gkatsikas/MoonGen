#!/bin/bash

acl_size=$1
pkt_size=$2
side=$3
lat_mode=$4

sudo MoonGen \
	trx-from-pcap-multiport.lua \
	2 10000000000 ${pkt_size} 0 \
	~/nfv/snf-controller/data/filter_covered/orig_acl_${acl_size}_${pkt_size}pcap2 \
	${lat_mode} ${side}
