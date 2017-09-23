--! @file tx.lua
--! @brief Send on a specific port with timestamping

local moongen   = require "moongen"
local memory    = require "memory"
local device    = require "device"
local stats     = require "stats"
local timer     = require "timer"
local log       = require "log"

local ETH_DST   = "52:54:55:B2:00:00"
local IP_SRC    = "96.0.0.1"
local IP_DST    = "136.0.0.1"
local PORT_SRC  = 1234
local PORT_DST  = 1234
local BASE_PORT = 1000
local NUM_PORTS = 60000 - BASE_PORT
local NUM_FLOWS = 254

local RUN_TIME	= 20
local RANDOMIZE = true

--Usage: sudo ../../build/MoonGen tx.lua 0 10000000000 60 100000000 1

function master(txPort, rate, pktSize, maxPackets, timestamping)
	local txPort, rate, pktSize, maxPackets = tonumberall(txPort, rate, pktSize, maxPackets)
	if not txPort or not rate or not pktSize or not maxPackets or not timestamping then
		return log:error("Usage: txPort rate pktSize maxPackets timestamping")
	end

	if (rate <= 0) then rate = 10000000000 end
	if (timestamping <= 0) then
		timestamping = false
	else
		timestamping = true
	end

	local queues  = 1
	--local txCores = {2, 4, 6, 8, 10, 12, 14}
	local txCores = {2}
	if (timestamping) then
		queues = #txCores
		rate = math.ceil(rate / queues) or (10000000000 / queues)
	end

	if (maxPackets <= 0) then maxPackets = nil
	else maxPackets = math.floor(maxPackets / queues) end

	log:info("   Tx   Port: %d", txPort)
	log:info("   Tx   Rate: %.2f Gbps", rate/1000000000)
	log:info("   Tx Queues: %d", queues)
	log:info("  Packets No: %d", maxPackets)
	log:info(" Packet Size: %d", pktSize)
	log:info("Timestamping: %s", timestamping)

	local txDev = device.config({port=txPort, txQueues=queues})
	txDev:wait()

	print("")
	for q = 0, queues-1 do
		local queue = txDev:getTxQueue(q)
		queue:setRate(rate)
		queue:enableTimestamps()

		local coreOfQueue = txCores[math.fmod(q, #txCores) + 1]
		log:info("[Core %2d] [Tx Queue %2d] Rate: %.2f Gbps", coreOfQueue, q, rate/1000000000)

		moongen.startTaskOnCore(coreOfQueue, "txTask", txPort, queue, q, coreOfQueue, maxPackets, pktSize, timestamping)
	end

	-- Counting
--	local devs = {txDev}
--	local ctr = moongen.startTaskOnCore(0, "txCounterTask", devs)
--	printTxStats(ctr:wait())

	moongen.waitForTasks()
end

--! @brief: A thread that transmits frames with randomized IPs and ports
function txTask(port, queue, queueNo, core, maxPacketsPerCore, pktSize, timestamping)
	-- Create a UDP packet template
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPtpPacket():fill{
			pktLength = pktSize, -- this sets the total frame length
			ethSrc    = queue,   -- get the src MAC from the device
			ethDst    = ETH_DST,
			-- payload will be initialized to 0x00 as new memory pools are initially empty
		}
	end)

	MAX_BURST_SIZE = 1
	if (not timestamping) then MAX_BURST_SIZE = 31 end

	local lastPrint = moongen.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent  = 0

	local bufs      = mem:bufArray(MAX_BURST_SIZE)

	local flow      = 0
	local baseSrcIP = parseIPAddress(IP_SRC)
	local baseDstIP = parseIPAddress(IP_DST)

	while (moongen.running()) and (not maxPacketsPerCore or totalSent <= maxPacketsPerCore) do
		-- Take a batch of  empty mbufs
		bufs:alloc(pktSize)

		-- Modify the IP addresses and ports of each packet
		for _, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()

			if ( RANDOMIZE ) then
				pkt.ip4.src:set(baseSrcIP + flow)
				pkt.ip4.dst:set(baseDstIP + flow)
				pkt.udp:setSrcPort(PORT_SRC + math.random(NUM_FLOWS) - 1)
				pkt.udp:setDstPort(PORT_DST + math.random(NUM_FLOWS) - 1)
			else
				pkt.ip4.src:set(baseSrcIP)
				pkt.ip4.dst:set(baseDstIP)
				pkt.udp:setSrcPort(PORT_SRC)
				pkt.udp:setDstPort(PORT_DST)
			end

			flow = incAndWrap(flow, NUM_FLOWS)
		end
		bufs:offloadUdpChecksums()

		-- Send packets, either timestamped or not
		local sent = 1
		if (timestamping) then queue:sendWithTimestamp(bufs)
		else sent = queue:send(bufs) end

		-- Count packets and throughput
		totalSent = totalSent + sent
		lastPrint, lastTotal = countAndPrintThroughputPerCore(queueNo, core, totalSent, lastPrint, lastTotal, pktSize)
	end

	moongen.sleepMillis(500)
	moongen.stop()
	log:info("[Core %2d] [Tx Queue %2d] Sent %d packets", core, queueNo, totalSent)
end

--! @brief: A thread that counts statistics about the transmitted packets
function txCounterTask(devs)
	local ctrs = map(devs, function(dev) return stats:newDevTxCounter(dev) end)
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

function printTxStats(ctr)
	local rates = {}
	rates[#rates+1] = ctr
	stats.addStats(rates)
	local freqInGHz = 3.20
	local cyclesPerPkt = freqInGHz * 10^3 / rates.avg
	local relStdDev = rates.stdDev / rates.avg
	log:info("[Tx] Cycles/Pkt: %.2f, StdDev: %.2f", cyclesPerPkt, cyclesPerPkt * relStdDev)
end

--! @brief: A method that "manually" derives the packet rate per core
function countAndPrintThroughputPerCore(queueNo, core, totalSent, lastPrint, lastTotal, pktSize)
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
