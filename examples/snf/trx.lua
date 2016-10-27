--! @file trx.lua
--! @brief Send and receiver on the same port with timestamping

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

local ffi	= require "ffi"

local ETH_DST   = "ec:f4:bb:d6:06:d8"
local IP_SRC    = "10.0.0.1"
local IP_DST    = "200.0.0.1"
local PORT_SRC  = 1234
local PORT_DST  = 1234
local BASE_PORT = 1000
--local NUM_PORTS = 60000 - BASE_PORT
local NUM_PORTS = 10
local NUM_FLOWS	= 254
local RUN_TIME  = 20
local txCounterSlaveOn = false

--Usage: sudo ../../build/MoonGen trx.lua 0 10000000000 60 100000000000 1

function master(trxPortNo, txRate, pktSize, maxTxPackets, timestamping)
	local trxPortNo, txRate, pktSize, maxTxPackets = tonumberall(trxPortNo, txRate, pktSize, maxTxPackets)
	if not trxPortNo or not txRate or not pktSize or not maxTxPackets or not timestamping then
		return log:info([[Usage: trxPortNo txRate pktSize maxTxPackets timestamping]])
	end

	local txCores    = {2, 4, 6, 8, 10, 12}
	local rxCores    = {14}
	
	if (timestamping <= 0) then timestamping = false
	else timestamping = true end

	local txQueuesNo = 1
	local rxQueuesNo = 1
	if (timestamping) then txQueuesNo = 6 end

	local txRate     = math.ceil(txRate / txQueuesNo) or (10000000000 / txQueuesNo)
	local txDev  = device.config{ port = trxPortNo, rxQueues = rxQueuesNo, txQueues = txQueuesNo}
	local rxDev  = txDev
	-- Wait until the links are up
	device.waitForLinks()

	if (maxTxPackets <= 0) then maxTxPackets = nil
	else maxTxPackets = math.floor(maxTxPackets / txQueuesNo) end

	print("Tx        Port: ", trxPortNo)
	print("Tx   Rate/Core: ", txRate/1000000000,"Gbps")
	print("Tx  Packets No: ", maxTxPackets)
	print("Tx Packet Size: ", pktSize)

	-- Tx threads
	for q = 0, txQueuesNo-1 do
		txDev:getTxQueue(q):setRate(txRate)
		local coreOfQueue = txCores[math.fmod(q, #txCores) + 1]
		mg.launchLuaOnCore(coreOfQueue ,"txSlave", trxPortNo, q, coreOfQueue, maxTxPackets, pktSize, timestamping)
	end

	-- Rx threads
	for q = 0, rxQueuesNo-1 do
		local coreOfQueue = rxCores[math.fmod(q, #rxCores) + 1]
		mg.launchLuaOnCore(coreOfQueue, "rxCounterSlave", rxDev, q, coreOfQueue, timestamping)
	end

	-- Tx counter
	if (timestamping) then 
		local txCtr = mg.launchLua("txCounterSlave", {txDev})
		printTxStats(txCtr:wait())
	end

	mg.waitForSlaves()
end

--! @brief: A thread that transmits frames with randomized IPs and ports
function txSlave(port, queueNo, core, maxPacketsPerCore, pktSize, timestamping)
	local queue = device.get(port):getTxQueue(queueNo)
	printf("[Core %d] [Queue %d] Tx Slave", core, queueNo)

	-- Create a UDP packet template
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = pktSize, -- this sets all length headers fields in all used protocols
			ethSrc    = queue,   -- get the src mac from the device
			ethDst    = ETH_DST,
			--ip4Src = IP_SRC, --ip4Dst = IP_DST, --udpSrc = PORT_SRC, --udpDst = PORT_DST,
			--payload will be initialized to 0x00 as new memory pools are initially empty
		}
	end)

	MAX_BURST_SIZE = 1
	if (not timestamping) then MAX_BURST_SIZE = 31 end

	local lastPrint = mg.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent  = 0

	local baseSrcIP = parseIPAddress(IP_SRC)
	local baseDstIP = parseIPAddress(IP_DST)
	-- a buf array is essentially a very thing wrapper around a rte_mbuf*[], 
	-- i.e. an array of pointers to packet buffers
	local bufs = mem:bufArray(MAX_BURST_SIZE)

	-- Positions of IP addresses in a frame
	local src_idx_start = 26
	local src_idx_end   = 26
	local dst_idx_start = 30
	local dst_idx_end   = 30

	while (mg.running()) and (not maxPacketsPerCore or totalSent <= maxPacketsPerCore) do
		bufs:alloc(pktSize)
		for _, buf in ipairs(bufs) do
			local data = ffi.cast("uint8_t*", buf.pkt.data)
			data[dst_idx_start] = 1 + math.random(NUM_FLOWS)
		
		--	-- Select randomized IP addresses and ports
		--	-- Change idx_end-idx_start bytes randomly
		--	--for i = src_idx_start, src_idx_end do
		--	--	data[i] = 1 + math.random(NUM_FLOWS)
		--	--end
		--	for i = dst_idx_start, dst_idx_end do
		--		data[i] = 1 + math.random(NUM_FLOWS)
		--	end
		--	--local pkt = buf:getUdpPacket()
		--	--pkt.ip4.src:set(baseSrcIP + math.random(NUM_FLOWS) - 1)
		--	--pkt.ip4.dst:set(baseDstIP + math.random(NUM_FLOWS) - 1)
		--
		--	-- Randmize ports as well
		--	--pkt.udp.src = (BASE_PORT + math.random(NUM_PORTS) - 1)
		--	--pkt.udp.dst = (BASE_PORT + math.random(NUM_PORTS) - 1)
		end
		--bufs:offloadUdpChecksums()

		-- Send packets
		local sent = 1
		if (timestamping) then queue:sendWithTimestamp(bufs)
		else sent = queue:send(bufs) end
		totalSent = totalSent + sent

		if (not txCounterSlaveOn) then
			lastPrint, lastTotal = countAndPrintThroughputPerCore(core, totalSent, lastPrint, lastTotal, pktSize)
		end
	end
	mg.sleepMillis(500)
	mg.stop()
	--printf("[Core %d] Sent %d packets", core, totalSent)
end

--! @brief: A thread that counts statistics about the transmitted packets
function txCounterSlave(devs)
	txCounterSlaveOn = true
	local ctrs = map(devs, function(dev) return stats:newDevTxCounter(dev) end)
	--local ctrs = stats:newDevTxCounter(dev)
	local runtime = timer:new(RUN_TIME - 1)
	mg.sleepMillisIdle(1000) -- measure the steady state
	while mg.running() and runtime:running() do
		for _, ctr in ipairs(ctrs) do
			ctr:update()
		end
		mg.sleepMillisIdle(10)
	end
	local tp, stdDev, sum = 0, 0, 0
	for _, ctr in ipairs(ctrs) do
		local mpps = ctr:getStats()
		tp = tp + mpps.avg
		stdDev = stdDev + mpps.stdDev
		sum = sum + mpps.sum
	end
	return tp, stdDev, sum
end

function rxCounterSlave(rxDev, queueNo, core, timestamping)
	local queue = rxDev:getRxQueue(queueNo)
	local tscFreq    = mg.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs = memory.bufArray(64)
	----if (timestamping) then queue.dev:filterTimestamps(queue) end

	local ctr     = stats:newDevRxCounter(rxDev, "plain")
	local pkts    = 0
	local rxts    = {}
	local results = {}
	while mg.running() do
		
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
		bufs:freeAll()
	end
	ctr:finalize()

	if (timestamping) then
		print("--- Latency calculator")
		dumpLatencyToFile(results)
	end

	printf("[Core %d] Rx terminated after receiving %d packets", core, pkts)
end

function printTxStats(ctr)
	local rates = {}
	rates[#rates+1] = ctr
	stats.addStats(rates)
	local freqInGHz = 3.20
	local cyclesPerPkt = freqInGHz * 10^3 / rates.avg
	local relStdDev = rates.stdDev / rates.avg
	print("[Tx] Cycles/Pkt: " .. cyclesPerPkt .. " StdDev: " .. cyclesPerPkt * relStdDev)
end

--! @brief: A method that "manually" derives the packet rate per core
function countAndPrintThroughputPerCore(core, totalSent, lastPrint, lastTotal, pktSize)
	-- Count throughput
	local time = mg.getTime()
	if time - lastPrint > 1 then
		local mpps = (totalSent - lastTotal) / (time - lastPrint) / 10^6
		printf("[Core %d] Sent %d packets, current rate %.2f Mpps, %.2f MBit/s, %.2f MBit/s wire rate", 
				core, totalSent, mpps, mpps * pktSize * 8, mpps * (pktSize+20) * 8)
		lastTotal = totalSent
		lastPrint = time
	end

	return lastPrint, lastTotal
end

function dumpLatencyToFile(results)
	local f = io.open("latency.dat", "w+")
	for i, v in ipairs(results) do
		f:write(v .. "\n")
	end
	f:close()
end
