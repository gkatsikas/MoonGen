--! @file rx-multiport.lua
--! @brief Receiver on a set of ports with timestamping

local moongen = require "moongen"
local memory  = require "memory"
local device  = require "device"
local stats   = require "stats"
local log     = require "log"

local DEV_LIST  = { 
	0,
	1,
	2,
	3
}

--Usage: sudo ../../build/MoonGen rx-multiport.lua 4 2000000 0

--! @brief: Start a number of Rx threads
function master(rxPortsNo, maxPackets, timestamping)
	local devices = device.getDevices()
	local rxPortsNo, maxPackets = tonumberall(rxPortsNo, maxPackets)

	if not rxPortsNo or not maxPackets or not timestamping then
		return log:info("Usage: rxPortsNo maxPackets timestamping")
	end

	if (rxPortsNo > #devices) then
		return log:error("Too many NICs. We support up to %d", #devices)
	end

	if (timestamping <= 0) then
		timestamping = false
	else
		timestamping = true
	end

	-- Non-zero maxPackets forces rx to stop after receiving that many packets.
	if (maxPackets <= 0) then maxPackets = nil end

	log:info("Number of Rx Ports: %d", rxPortsNo)
	log:info("        Packets No: %d", maxPackets)

	local rxQueuesNo = 1
	local rxCores    = { {2}, {4}, {6}, {8} }

	-- Configure each device for Tx
	local rxDevs = {}
	for i=0, rxPortsNo-1 do
		local dev = device.config{ port=DEV_LIST[i+1], rxQueues=rxQueuesNo }
		rxDevs[#rxDevs+1] = dev
	end
	-- Wait until the links are up
	device.waitForLinks()

	-- Rx threads
	for i = 0, #rxDevs-1 do
		local coreOfQueue = rxCores[i+1][1]
		log:info("[Dev %d] Core %2d", i, coreOfQueue)
		moongen.startTaskOnCore(coreOfQueue, "rxCounterTask", i, rxDevs[i+1], 0, coreOfQueue, timestamping)
		--moongen.startTaskOnCore(coreOfQueue, "rxTask",        i, rxDevs[i+1], 0, coreOfQueue, timestamping)
	end
	moongen.waitForTasks()
end

function rxCounterTask(rxDevNo, rxDev, queueNo, core, timestamping)
	log:info("[Dev %d] [Core %2d] [Rx Queue %2d] Rx Task", rxDevNo, queueNo, core)
	local queue = rxDev:getRxQueue(queueNo)
	local bufs = memory.bufArray()
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	local pkts = 0
	while moongen.running() do
		local rx = queue:recv(bufs)
		pkts = pkts + rx
		ctr:update()
		bufs:freeAll()
	end
	ctr:finalize()
	log:info("[Core %2d] [Rx Queue %2d] Received %d packets", core, 1, pkts)
end

--! @brief: Receive and store packets with software timestamps
function rxTask(rxDevNo, rxDev, maxPackets, core, timestamping)
	local queue   = rxDev:getRxQueue(0)
	local tscFreq = moongen.getCyclesFrequency()
	local bufs    = memory.bufArray(64)

	-- use whatever filter appropriate for your packet type
	queue:filterUdpTimestamps()

	local ctr     = stats:newDevRxCounter(rxDev, "plain")
	local pkts    = 0
	local rxts    = {}
	local results = {}
	while (moongen.running()) and (maxPackets == 0 or pkts < maxPackets) do

		-- Receiver that timestamps in software
		local rx
		if (timestamping) then rx = queue:recvWithTimestamps(bufs)
		else rx = queue:recv(bufs) end

		-- Calculate the latencies of this batch
		if (timestamping) then
			for i = 1, rx do
				local rxTs = bufs[i].udata64
				local txTs = bufs[i]:getSoftwareTxTimestamp()
				results[#results + 1] = tonumber(rxTs - txTs) / tscFreq * 10^9 -- to nanoseconds
				rxts[#rxts + 1] = tonumber(rxTs)
			end
		end

		pkts = pkts + rx
		ctr:update()
		bufs:free(rx)
	end
	ctr:finalize()

	log:info("[Core %2d] [Rx Queue %2d] Received %d packets", core, 1, pkts)

	if (timestamping) then
		log:info("Latency calculator")
		dumpLatencyToFile(results)
		log:info("\t Done")
	end
end

function dumpLatencyToFile(results)
	local f = io.open("latency.dat", "w+")
	for i, v in ipairs(results) do
		f:write(v .. "\n")
	end
	f:close()
end

