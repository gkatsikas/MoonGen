#!/bin/bash

port=$1
pkts_no=$2
ts=$3

# Example: sudo ./run_rx.sh 0 50000000 0

sudo ../../build/MoonGen rx.lua $port $pkts_no $ts
