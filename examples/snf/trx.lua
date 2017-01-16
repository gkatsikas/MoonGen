--! @file trx.lua
--! @brief Send and receiver on the same port with timestamping

local moongen   = require "moongen"
local memory    = require "memory"
local device    = require "device"
local stats     = require "stats"
local timer     = require "timer"
local log       = require "log"

local ETH_DST   = "ec:f4:bb:d6:06:d8"
local IP_SRC    = "10.0.0.1"
local IP_DST    = "200.0.0.1"
local PORT_SRC  = 1234
local PORT_DST  = 1234
local BASE_PORT = 1000
local NUM_PORTS = 60000 - BASE_PORT
local NUM_PORTS = 10
local NUM_FLOWS = 254
local RUN_TIME  = 20
local TX_COUNTER_SLAVE_ON = false

--Usage: sudo ../../build/MoonGen trx.lua 0 10000000000 60 100000000000 1

function master(trxPortNo, txRate, pktSize, maxTxPackets, timestamping)
	local trxPortNo, txRate, pktSize, maxTxPackets = tonumberall(trxPortNo, txRate, pktSize, maxTxPackets)
	if not trxPortNo or not txRate or not pktSize or not maxTxPackets or not timestamping then
		return log:error("Usage: trxPortNo txRate pktSize maxTxPackets timestamping")
	end

	local txCores = {2, 4, 6, 8, 10, 12}
	local rxCores = {14}
	
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

	log:info("TRx          Port: %d", trxPortNo)
	log:info("Tx         Queues: %d", txQueuesNo)
	log:info("Rx         Queues: %d", rxQueuesNo)
	log:info("Tx      Rate/Core: %.2f Gbps", txRate/1000000000)
	log:info("Tx  Packets/Queue: %.2f", maxTxPackets)
	log:info("Tx    Packet Size: %d", pktSize)

	-- Tx threads
	for q = 0, txQueuesNo-1 do
		txDev:getTxQueue(q):setRate(txRate)
		local coreOfQueue = txCores[math.fmod(q, #txCores) + 1]
		moongen.startTaskOnCore(coreOfQueue ,"txTask", trxPortNo, q, coreOfQueue, maxTxPackets, pktSize, timestamping)
	end

	-- Rx threads
	for q = 0, rxQueuesNo-1 do
		local coreOfQueue = rxCores[math.fmod(q, #rxCores) + 1]
		moongen.startTaskOnCore(coreOfQueue, "rxCounterTask", rxDev, q, coreOfQueue, timestamping)
	end

	-- Tx counter
--	if (timestamping) then 
--		local txCtr = moongen.launchLua("txCounterTask", {txDev})
--		printTxStats(txCtr:wait())
--	end

	moongen.waitForTasks()
end

--! @brief: A thread that transmits frames with randomized IPs and ports
function txTask(port, queueNo, core, maxPacketsPerCore, pktSize, timestamping)
	local queue = device.get(port):getTxQueue(queueNo)
	log:info("[Core %2d] [Tx Queue %2d] Tx Task", core, queueNo)

	-- Create a UDP packet template
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = pktSize, -- this sets the total frame length
			ethSrc    = queue,   -- get the src MAC from the device
			ethDst    = ETH_DST,
			--payload will be initialized to 0x00 as new memory pools are initially empty
		}
	end)

	MAX_BURST_SIZE = 1
	if (not timestamping) then MAX_BURST_SIZE = 31 end

	local lastPrint = moongen.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent  = 0

	-- a buf array is essentially a very thin wrapper around a rte_mbuf*[]
	local bufs = mem:bufArray(MAX_BURST_SIZE)

	local flow      = 0
	local baseSrcIP = parseIPAddress(IP_SRC)
	local baseDstIP = parseIPAddress(IP_DST)

	while (moongen.running()) and (not maxPacketsPerCore or totalSent <= maxPacketsPerCore) do
		-- Take a batch of  empty mbufs
		bufs:alloc(pktSize)

		for _, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()

			-- Modify the IP addresses and ports of each packet
			pkt.ip4.src:set(baseSrcIP + flow)
			pkt.ip4.dst:set(baseDstIP + flow)
			pkt.udp:setSrcPort(PORT_SRC + math.random(NUM_FLOWS) - 1)
			pkt.udp:setDstPort(PORT_DST + math.random(NUM_FLOWS) - 1)

			flow = incAndWrap(flow, NUM_FLOWS)
		end
		bufs:offloadUdpChecksums()

		-- Send packets, either timestamped or not
		local sent = 1
		if (timestamping) then queue:sendWithTimestamp(bufs)
		else sent = queue:send(bufs) end

		-- Count packets
		totalSent = totalSent + sent

		-- Count throughput
		if (TX_COUNTER_SLAVE_ON) then
			lastPrint, lastTotal = countAndPrintThroughputPerCore(core, queueNo, totalSent, lastPrint, lastTotal, pktSize)
		end
	end

	moongen.sleepMillis(500)
	moongen.stop()
	log:info("[Core %2d] [Tx Queue %2d] Sent %d packets", core, queueNo, totalSent)
end

--! @brief: A thread that counts statistics about the transmitted packets
function txCounterTask(devs)
	TX_COUNTER_SLAVE_ON = true
	local ctrs = map(devs, function(dev) return stats:newDevTxCounter(dev) end)
	--local ctrs = stats:newDevTxCounter(dev)

	local runtime = timer:new(RUN_TIME - 1)
	moongen.sleepMillisIdle(1000) -- measure the steady state
	while moongen.running() and runtime:running() do
		for _, ctr in ipairs(ctrs) do
			ctr:update()
		end
		moongen.sleepMillisIdle(10)
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

function rxCounterTask(rxDev, queueNo, core, timestamping)
	local queue      = rxDev:getRxQueue(queueNo)
	local tscFreq    = moongen.getCyclesFrequency()
	local bufs       = memory.bufArray(64)

	-- use whatever filter appropriate for your packet type
	queue:filterUdpTimestamps()

	local ctr     = stats:newDevRxCounter(rxDev, "plain")
	local pkts    = 0
	local rxts    = {}
	local results = {}

	while moongen.running() do
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

	if (timestamping) then
		log:info("[Core %2d] [Tx Queue %2d] Latency calculator", core, queueNo)
		dumpLatencyToFile(results)
	end

	log:info("[Core %2d] [Tx Queue %2d] Received %d packets", core, queueNo, pkts)
end

--! @brief: A method that prints Tx statistics (CPU cycles/packet)
function printTxStats(ctr)
	local rates = {}
	rates[#rates+1] = ctr
	stats.addStats(rates)
	local freqInGHz = 3.20
	local cyclesPerPkt = freqInGHz * 10^3 / rates.avg
	local relStdDev = rates.stdDev / rates.avg
	log:info("[Tx] Cycles/Pkt: %.2f, StdDev: %.3f", cyclesPerPkt, cyclesPerPkt * relStdDev)
end

--! @brief: A method that "manually" derives the packet rate per core
function countAndPrintThroughputPerCore(core, queueNo, totalSent, lastPrint, lastTotal, pktSize)
	-- Count throughput
	local time = moongen.getTime()
	if time - lastPrint > 1 then
		local mpps = (totalSent - lastTotal) / (time - lastPrint) / 10^6
		log:info("[Core %2d] [Tx Queue %2d] Sent %d packets, current rate %.2f Mpps, %.2f MBit/s, %.2f MBit/s wire rate", 
				core, queueNo, totalSent, mpps, mpps * pktSize * 8, mpps * (pktSize+20) * 8)
		lastTotal = totalSent
		lastPrint = time
	end

	return lastPrint, lastTotal
end

--! @brief: A method that dumps the collected packet latencies to a file
function dumpLatencyToFile(results)
	local f = io.open("latency.dat", "w+")
	for i, v in ipairs(results) do
		f:write(v .. "\n")
	end
	f:close()
end
