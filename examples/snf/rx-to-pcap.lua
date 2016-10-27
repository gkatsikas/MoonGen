--! @file rx-to-pcap.lua
--! @brief Capture to PCAP with software timestamping

local mg	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local ts	= require "timestamping"
local dpdkc	= require "dpdkc"
local filter	= require "filter"

local stats	= require "stats"
local hist	= require "histogram"
local timer	= require "timer"
local log	= require "log"
local pcap	= require "pcap"

local ffi	= require "ffi"

--Usage: sudo MoonGen examples/snf/rx-to-pcap.lua 0 15000000

--! @brief: Start a number of Rx threads, one per queue
function master(rxPort, maxPackets)
	local rxPort, maxPackets = tonumberall(rxPort, maxPackets)
	if not rxPort or not maxPackets then
		return log:info([[Usage: rxPort maxPackets]])
	end

	-- Non-zero maxPackets forces rx to stop after receiving that many packets.
	if (maxPackets <= 0) then maxPackets = nil end

	print(" Rx   Port: ", rxPort)
	print("Packets No: ", maxPackets)

	local queues = 1
	local rxDev  = device.config({port=rxPort, rxQueues=queues})
	rxDev:wait()
	mg.launchLua("rxSlave", rxPort, rxDev, maxPackets)
	mg.waitForSlaves()
end

--! @brief: Receive and store packets with software timestamps
function rxSlave(port, rxDev, maxPackets)
	local queue = device.get(port):getRxQueue(0)
	sink = "pcap-port-"..port..".pcap"

	local numbufs = (maxPackets == 0) and 100 or math.min(100, maxPackets)
	local bufs = memory.bufArray(numbufs)
	local timestamps = ffi.new("uint64_t[?]", numbufs)
	queue.dev:filterTimestamps(queue)

	local pcapSinkWriter = pcapWriter:newPcapWriter(sink)
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	local pkts = 0
	while mg.running() and (maxPackets == 0 or pkts < maxPackets) do
		local rxnum = (maxPackets == 0) and #bufs or math.min(#bufs, maxPackets - pkts)
		local rx = queue:recvWithTimestamps(bufs, timestamps, rxnum)
		pcapSinkWriter:writeTSC(bufs, timestamps, rx, true)
		pkts = pkts + rx
		ctr:update()
		bufs:free(rx)
	end
	bufs:freeAll()
	ctr:finalize()
	pcapSinkWriter:close()
	mg.sleepMillis(500)
	mg.stop()

	printf("[Rx Port %d] Terminated after receiving %d packets", port, pkts)
end
