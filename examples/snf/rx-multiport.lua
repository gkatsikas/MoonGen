--! @file rx-multiport.lua
--! @brief Receiver on a set of ports with timestamping

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

local DEV_LIST  = { 
	0,
	1,
	2,
	3
}

--Usage: sudo ../../build/MoonGen rx-multiport.lua 4 2000000 0

--! @brief: Start a number of Rx threads
function master(rxPortsNo, maxPackets, timestamping)
	local rxPortsNo, maxPackets = tonumberall(rxPortsNo, maxPackets)
	if not rxPortsNo or not maxPackets or not timestamping then
		return log:info([[Usage: rxPortsNo maxPackets timestamping]])
	end

	if (rxPortsNo > 4) then
		return log:info([[Too many NICs. We support up to 4.]])
	end

	if (timestamping <= 0) then
		timestamping = false
	else
		timestamping = true
	end

	-- Non-zero maxPackets forces rx to stop after receiving that many packets.
	if (maxPackets <= 0) then maxPackets = nil end

	print("Number of Rx Ports: ", rxPortsNo)
	print("        Packets No: ", maxPackets)

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
		printf("[Dev %d] [Rx Queue 0] Core: %d", i, coreOfQueue)
		mg.launchLuaOnCore(coreOfQueue, "rxCounterSlave", i, rxDevs[i+1], 0, coreOfQueue, timestamping)
		--mg.launchLuaOnCore(coreOfQueue, "rxSlave", i, rxDevs[i+1], 0, coreOfQueue, timestamping)
	end
	mg.waitForSlaves()
end

function rxCounterSlave(rxDevNo, rxDev, queueNo, core, timestamping)
	printf("[Dev %d] [Queue %d] [Core %d] Rx Slave", rxDevNo, queueNo, core)
	local queue = rxDev:getRxQueue(queueNo)
	local bufs = memory.bufArray()
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	local pkts = 0
	while mg.running() do
		local rx = queue:recv(bufs)
		pkts = pkts + rx
		ctr:update()
		bufs:freeAll()
	end
	ctr:finalize()
	printf("[Core %d] Rx terminated after receiving %d packets", core, pkts)
end

--! @brief: Receive and store packets with software timestamps
function rxSlave(rxDevNo, rxDev, maxPackets, timestamping)
	local queue = rxDev:getRxQueue(0)

	local tscFreq    = mg.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs = memory.bufArray(64)
	----if (timestamping) then queue.dev:filterTimestamps(queue) end

	if (timestamping) then 
		print("TIMESTAMPING")
	end

	local ctr     = stats:newDevRxCounter(rxDev, "plain")
	local pkts    = 0
	local rxts    = {}
	local results = {}
	while (mg.running()) and (maxPackets == 0 or pkts < maxPackets) do

		-- Receiver that time-stamps in software
		local rx
		if (timestamping) then rx = queue:recvWithTimestamps(bufs, timestamps)
		else rx = queue:recv(bufs) end

		-- Calculate the latencies of this batch
		--if (timestamping) and (math.fmod(pkts, 2) == 0) then
		if (timestamping) then
			for i = 1, rx do
				--if ( math.fmod(i, 2) == 0 ) then 
					local rxTs = timestamps[i - 1]
					local txTs = bufs[i]:getSoftwareTxTimestamp()
					results[#results + 1] = tonumber(rxTs - txTs) / tscFreq * 10^9 -- to nanoseconds
					rxts[#rxts + 1] = tonumber(rxTs)
				--end
			end
		end

		pkts = pkts + rx
		ctr:update()
		bufs:free(rx)
	end
	ctr:finalize()

	if (timestamping) then
		print("--- Latency calculator")
		dumpLatencyToFile(results)
	end

	printf("[Rx Port %d] Terminated after receiving %d packets", rxDevNo, pkts)
end

function dumpLatencyToFile(results)
	local f = io.open("latency.dat", "w+")
	for i, v in ipairs(results) do
		f:write(v .. "\n")
	end
	f:close()
end

