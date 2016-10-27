--! @file rx.lua
--! @brief Receiver on a specific port with timestamping

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

--Usage: sudo ../../build/MoonGen rx.lua 0 2000000 1

--! @brief: Start a number of Rx threads
function master(rxPort, maxPackets, timestamping)
	local rxPort, maxPackets = tonumberall(rxPort, maxPackets)
	if not rxPort or not maxPackets or not timestamping then
		return log:info([[Usage: rxPort maxPackets timestamping]])
	end

	if (timestamping <= 0) then
		timestamping = false
	else
		timestamping = true
	end

	-- Non-zero maxPackets forces rx to stop after receiving that many packets.
	if (maxPackets <= 0) then maxPackets = nil end

	print("   Rx  Port: ", rxPort)
	print(" Packets No: ", maxPackets)

	local queues = 1
	local rxDev  = device.config({port=rxPort, rxQueues=queues})
	rxDev:wait()
	mg.launchLuaOnCore(2, "rxSlave", rxPort, rxDev, maxPackets, timestamping)
	mg.waitForSlaves()
end

--! @brief: Receive and store packets with software timestamps
function rxSlave(port, rxDev, maxPackets, timestamping)
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

	printf("[Rx Port %d] Terminated after receiving %d packets", port, pkts)
end

function dumpLatencyToFile(results)
	local f = io.open("latency.dat", "w+")
	for i, v in ipairs(results) do
		f:write(v .. "\n")
	end
	f:close()
end
