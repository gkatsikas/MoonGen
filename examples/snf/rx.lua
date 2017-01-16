--! @file rx.lua
--! @brief Receiver on a specific port with timestamping

local moongen  = require "moongen"
local memory   = require "memory"
local device   = require "device"
local stats    = require "stats"
local log      = require "log"

--Usage: sudo ../../build/MoonGen rx.lua 0 200000000 1

--! @brief: Start a number of Rx threads
function master(rxPort, maxPackets, timestamping)
	local rxPort, maxPackets = tonumberall(rxPort, maxPackets)
	if not rxPort or not maxPackets or not timestamping then
		return log:error("Usage: rxPort maxPackets timestamping")
	end

	if (timestamping <= 0) then
		timestamping = false
	else
		timestamping = true
	end

	-- Non-zero maxPackets forces rx to stop after receiving that many packets.
	if (maxPackets <= 0) then maxPackets = nil end

	log:info("    Rx  Port: %d", rxPort)
	log:info("  Packets No: %d", maxPackets)
	log:info("Timestamping: %s", timestamping)

	local queues = 1
	local rxDev  = device.config({port=rxPort, rxQueues=queues})
	rxDev:wait()

	local rxCore = 2
	moongen.startTaskOnCore(rxCore, "rxTask", rxCore, rxPort, rxDev, maxPackets, timestamping)
	moongen.waitForTasks()
end

--! @brief: Receive and store packets with software timestamps
function rxTask(core, port, rxDev, maxPackets, timestamping)
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
		local rx = 0
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

	log:info("[Core %2d] [Rx Queue %2d] Received %d packets", core, port, pkts)

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
