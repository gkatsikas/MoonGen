#!/bin/bash

port=$1
rate=$2
pkt_size=$3
pkts_no=$4
ts=$5

# Example: sudo ./run_tx.sh 0 10000 64 50000000 0

sudo ../../build/MoonGen tx.lua $port $rate $pkt_size $pkts_no $ts
