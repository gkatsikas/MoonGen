#!/bin/bash

acl_size=$1
pkt_size=$2
side=$3
lat_mode=$4

# Example: sudo ./run_trx_acls.sh 8550 64 left 0

sudo ../../build/MoonGen \
	trx-from-pcap-multiport.lua \
	2 10000000000 $pkt_size 0 \
	/home/katsikas/nfv/snf-controller/data/filter_covered/orig_acl_${acl_size}_${pkt_size}_pcap2 \
	$lat_mode $side
