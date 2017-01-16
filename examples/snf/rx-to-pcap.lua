--! @file rx-to-pcap.lua
--! @brief Capture to PCAP with software timestamping

local moongen = require "moongen"
local memory  = require "memory"
local device  = require "device"
local stats   = require "stats"
local log     = require "log"
local pcap    = require "pcap"
local ffi     = require "ffi"

--Usage: sudo ../../build/MoonGen rx-to-pcap.lua 0 15000000

--! @brief: Start a number of Rx threads, one per queue
function master(rxPort, maxPackets)
	local rxPort, maxPackets = tonumberall(rxPort, maxPackets)
	if not rxPort or not maxPackets then
		return log:error("Usage: rxPort maxPackets")
	end

	-- Non-zero maxPackets forces rx to stop after receiving that many packets.
	if (maxPackets <= 0) then maxPackets = nil end

	log:info(" Rx   Port: %d", rxPort)
	log:info("Packets No: %d", maxPackets)

	local queues = 1
	local rxDev  = device.config({port=rxPort, rxQueues=queues})
	rxDev:wait()
	moongen.startTask("rxTask", rxPort, rxDev, maxPackets)
	moongen.waitForTasks()
end

--! @brief: Receive and store packets with software timestamps
function rxTask(port, rxDev, maxPackets)
	local queue = device.get(port):getRxQueue(0)
	sink = "pcap-port-"..port..".pcap"

	local numbufs = (maxPackets == 0) and 100 or math.min(100, maxPackets)
	local bufs = memory.bufArray(numbufs)
	local timestamps = ffi.new("uint64_t[?]", numbufs)
	queue.dev:filterUdpTimestamps(queue)

	local pcapSinkWriter = pcapWriter:newPcapWriter(sink)
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	local pkts = 0
	while moongen.running() and (maxPackets == 0 or pkts < maxPackets) do
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
	moongen.sleepMillis(500)
	moongen.stop()

	log:info("[Rx Port %d] Received %d packets", port, pkts)
end
