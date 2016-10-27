--! @file tx.lua
--! @brief Send on a specific port with timestamping

local mg	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local ts	= require "timestamping"
local dpdkc	= require "dpdkc"
local filter	= require "filter"

local stats	= require "stats"
local hist	= require "histogram"
local timer	= require "timer"

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

--Usage: sudo MoonGen examples/snf/tx.lua 0 10000000000 60 100000000 1

function master(txPort, rate, pktSize, maxPackets, timestamping)
	local txPort, rate, pktSize, maxPackets = tonumberall(txPort, rate, pktSize, maxPackets)
	if not txPort or not rate or not pktSize or not maxPackets or not timestamping then
		return log:info([[Usage: txPort rate pktSize maxPackets timestamping]])
	end

	if (rate <= 0) then rate = 10000000000 end
	if (timestamping <= 0) then
		timestamping = false
	else
		timestamping = true
	end

	local queues  = 1
	local txCores = {2, 4, 6, 8, 10, 12, 14}
	if (timestamping) then
		queues = 7
		rate = math.ceil(rate / queues) or (10000000000 / queues)
	end

	if (maxPackets <= 0) then maxPackets = nil
	else maxPackets = math.floor(maxPackets / queues) end

	print("   Tx   Port: ", txPort)
	print("   Tx   Rate: ", rate/1000000000,"Gbps")
	print("   Tx Queues: ", queues)
	print("  Packets No: ", maxPackets)
	print(" Packet Size: ", pktSize)
	print("Timestamping: ", timestamping)

	local txDev = device.config({port=txPort, txQueues=queues})
	txDev:wait()
	for q = 0, queues-1 do
		local queue = txDev:getTxQueue(q)
		queue:setRate(rate)
		queue:enableTimestamps()
		local coreOfQueue = txCores[math.fmod(q, #txCores) + 1]
		printf("\t[Tx Queue %d] Core: %d, Rate: %d", q, coreOfQueue, rate)
		mg.launchLuaOnCore(coreOfQueue, "txSlave", txPort, queue, coreOfQueue, maxPackets, pktSize, timestamping)
	end

	-- Counting
	--local devs = {txDev}
	--local ctr = mg.launchLuaOnCore(0, "txCounterSlave", devs)
	--printTxStats(ctr:wait())

	mg.waitForSlaves()
end

--! @brief: A thread that transmits frames with randomized IPs and ports
function txSlave(port, queue, core, maxPacketsPerCore, pktSize, timestamping)
	-- Create a UDP packet template
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPtpPacket():fill{
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

	local bufs = mem:bufArray(MAX_BURST_SIZE)

	-- First byte of dst IP address in a frame
	local dst_idx = 30

	while (mg.running()) and (not maxPacketsPerCore or totalSent <= maxPacketsPerCore) do
		bufs:alloc(pktSize)
		--for _, buf in ipairs(bufs) do
		--	local data = ffi.cast("uint8_t*", buf.pkt.data)
		--	data[dst_idx] = 1 + math.random(NUM_FLOWS)
		--end
		--bufs:offloadUdpChecksums()

		local sent = 1
		if (timestamping) then queue:sendWithTimestamp(bufs)
		else sent = queue:send(bufs) end
		totalSent = totalSent + sent
		--lastPrint, lastTotal = countAndPrintThroughputPerCore(core, totalSent, lastPrint, lastTotal, pktSize)
	end
	mg.sleepMillis(500)
	mg.stop()
	printf("[Core %d] Sent %d packets", core, totalSent)
end

--! @brief: A thread that counts statistics about the transmitted packets
function txCounterSlave(devs)
	local ctrs = map(devs, function(dev) return stats:newDevTxCounter(dev) end)
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
