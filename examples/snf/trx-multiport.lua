--! @file trx-multiport.lua
--! @brief Send and receive on a set of ports with timestamping

local moongen = require "moongen"
local memory  = require "memory"
local device  = require "device"
local ts      = require "timestamping"
local stats   = require "stats"
local hist    = require "histogram"
local timer   = require "timer"
local log     = require "log"
local ffi     = require "ffi"

local ETH_DST = "ec:f4:bb:d6:06:d8"
local IP_SRC  = "1.0.0.1"

------------------
-- 40 Gbps traffic
------------------
local IP_SRC_LEFT  = { 
	"1.0.0.2",
	"2.0.0.2",
	"3.0.0.2",
	"4.0.0.2"
}

local IP_SRC_RIGHT = { 
	"250.0.0.2",
	"251.0.0.2",
	"252.0.0.2",
	"253.0.0.2"
}

--local IP_DST_LEFT  = { 
--	"150.0.0.2",
--	"200.0.0.2",
--	"200.0.0.2",
--	"150.0.0.2"
--}

--local IP_DST_RIGHT = { 
--	"10.0.0.2",
--	"100.0.0.2",
--	"100.0.0.2",
--	"10.0.0.2"
--}

-- For HW timestamping packets should return to the same machine
local IP_DST_LEFT = { 
	"100.0.0.2",
	"10.0.0.2",
	"100.0.0.2",
	"10.0.0.2"
}

local IP_DST_RIGHT  = { 
	"200.0.0.2",
	"150.0.0.2",
	"200.0.0.2",
	"150.0.0.2"
}

------------------
-- 20 Gbps traffic
------------------
--local IP_SRC_LEFT  = { 
--	"1.0.0.2",
--	"2.0.0.2",
--	"3.0.0.2",
--	"4.0.0.2"
--}

--local IP_DST_LEFT  = { 
--	"200.0.0.2",
--	"10.0.0.2",
--	"100.0.0.2",
--	"150.0.0.2"
--}

local PORT_SRC  = 1234
local PORT_DST  = 1234
local BASE_PORT = 1000

local PTP_PORT_SRC = 1000
local PTP_PORT_DST = 1000

local NUM_PORTS = 10
local NUM_FLOWS	= 250
local RUN_TIME  = 20

--Usage: sudo ../../build/MoonGen trx-multiport.lua 2 10000000000 60 100000000000 0 left

function master(trxPortsNo, txRate, pktSize, maxTxPackets, timestamping, side)
	local trxPortsNo, txRate, pktSize, maxTxPackets = tonumberall(trxPortsNo, txRate, pktSize, maxTxPackets)
	if not trxPortsNo or not txRate or not pktSize or not maxTxPackets or not timestamping or not side then
		return log:info([[Usage: #ofTRxPorts txRate pktSize maxTxPackets timestamping side]])
	end

	if (trxPortsNo > 3) then
		return log:info([[Too many NICs. We support up to 3.]])
	end

	if (timestamping <= 0) then timestamping = false
	else timestamping = true end

	if ( (side == 0) or (side == "left") ) then
		side = "left"
	else
		side = "right"
	end

	local txQueuesNo = 2
	local rxQueuesNo = 2
	local txCores    = { {2}, {4}, {6}, {8} }
	local rxCores    = { {10}, {12}, {14}, {14} }

	if (maxTxPackets <= 0) then maxTxPackets = nil end
	-- We divide the total rate among all requested cores
	txRate = (txRate / txQueuesNo) or (10000000000 / txQueuesNo)

	log:info("Number of Tx Ports: %d", trxPortsNo)
	log:info("Number of Rx Ports: %d", trxPortsNo)
	log:info("    Tx   Rate/Core: %.2f Gbps", txRate/1000000000)
	log:info("    Tx  Packets No: %d", maxTxPackets)
	log:info("    Tx Packet Size: %d", pktSize)
	log:info("              Side: %s", side)

	-- Configure each device for Tx
	local txDevs = {}
	local rxDevs = {}
	for i=0, trxPortsNo-1 do
		local dev = device.config{ port=i, rxQueues=rxQueuesNo, txQueues=txQueuesNo }
		txDevs[#txDevs+1] = dev
		rxDevs[#rxDevs+1] = dev
	end
	-- Wait until the links are up
	device.waitForLinks()

	-- Tx threads (We transmit in a single queue per port)
	local txQueue = 0
	for i=0, #txDevs-1 do
		txDevs[i+1]:getTxQueue(txQueue):setRate(txRate)
		local coreOfQueue = txCores[i+1][math.fmod(txQueue, #txCores) + 1]
		log:info("[Dev %d] [Tx Queue %d] Core: %d",  i, txQueue, coreOfQueue)
		moongen.startTaskOnCore(coreOfQueue ,"txTask", i, txQueue, coreOfQueue, maxTxPackets, pktSize, false, side)
		--break
	end

	-- Rx threads (We receive from a single queue per port)
	for i = 0, #rxDevs-1 do
		local coreOfQueue = rxCores[i+1][1]
		log:info("[Dev %d] [Rx Queue 0] Core: %d", i, coreOfQueue)
		moongen.startTaskOnCore(coreOfQueue, "rxCounterTask", i, rxDevs[i+1], 0, coreOfQueue)
	end

	-- Tx counter
	local txCtr = moongen.startTask("txCounterTask", txDevs)

	-- HW-based Timestampers
	if (timestamping) then 
		log:info("Hardware Timestampers")
		hwTimestampers(trxPortsNo, txDevs, rxDevs, side)
	end

	local tp = txCtr:wait()
	printTxStats(tp)

	moongen.waitForTasks()
end

--! @brief: A thread that transmits frames with randomized IPs and ports
function txTask(port, queueNo, core, maxPacketsPerCore, pktSize, timestamping, side)
	local queue = device.get(port):getTxQueue(queueNo)
	log:info("[Dev %d] [Queue %d] [Core %d] Tx Slave", port, queueNo, core)

	local src_subnet_list
	local dst_subnet_list
	if ( side == "left" ) then
		src_subnet_list = IP_SRC_LEFT
		dst_subnet_list = IP_DST_LEFT
	else
		src_subnet_list = IP_SRC_RIGHT
		dst_subnet_list = IP_DST_RIGHT
	end

	-- Create a UDP packet template
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = pktSize, -- this sets all length headers fields in all used protocols
			ethSrc    = queue,   -- get the src mac from the device
			ethDst    = ETH_DST,
			ip4Src    = IP_SRC, --src_subnet_list[port + 1],
			ip4Dst    = dst_subnet_list[port + 1],  -- Each Tx thread sends packet to a different subnet
			--udpSrc = PORT_SRC,
			--udpDst = PORT_DST,
			--payload will be initialized to 0x00 as new memory pools are initially empty
		}
	end)

	MAX_BURST_SIZE = 1
	if (not timestamping) then MAX_BURST_SIZE = 31 end

	local lastPrint = moongen.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent  = 0

	local baseSrcIP = parseIPAddress(IP_SRC)
	local baseDstIP = parseIPAddress(IP_DST)
	-- a buf array is essentially a very thing wrapper around a rte_mbuf*[], 
	-- i.e. an array of pointers to packet buffers
	local bufs = mem:bufArray(MAX_BURST_SIZE)

	-- Positions of IP addresses in a frame
	local src_idx_start = 29 -- 26-29
	local src_idx_end   = 29
	local dst_idx_start = 30 -- 30-33
	local dst_idx_end   = 30

	while (moongen.running()) and (not maxPacketsPerCore or totalSent <= maxPacketsPerCore) do
		bufs:alloc(pktSize)

		for _, buf in ipairs(bufs) do
			-- TOFIX: buf.pkt.data replaced by buf.udata64
			local data = ffi.cast("uint8_t*", buf.udata64)
			-- Select randomized IP addresses and ports
			-- Change idx_end-idx_start bytes randomly
			for i = src_idx_start, src_idx_end do
				data[i] = 1 + math.random(NUM_FLOWS)
			end
			--for i = dst_idx_start, dst_idx_end do
			--	data[i] = 1 + math.random(NUM_FLOWS)
			--end

			--local pkt = buf:getUdpPacket()
			--pkt.ip4.src:set(baseSrcIP + math.random(NUM_FLOWS) - 1)
			--pkt.ip4.dst:set(baseDstIP + math.random(NUM_FLOWS) - 1)

			-- Randmize ports as well
			--pkt.udp.src = (BASE_PORT + math.random(NUM_PORTS) - 1)
			--pkt.udp.dst = (BASE_PORT + math.random(NUM_PORTS) - 1)
		end
		bufs:offloadUdpChecksums()

		-- Send packets
		local sent = 1
		if (timestamping) then queue:sendWithTimestamp(bufs)
		else sent = queue:send(bufs) end
		totalSent = totalSent + sent

		--lastPrint, lastTotal = countAndPrintThroughputPerCore(core, totalSent, lastPrint, lastTotal, pktSize)
	end
	moongen.sleepMillis(500)
	moongen.stop()
	--log:info("[Core %d] Sent %d packets", core, totalSent)
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

function rxCounterTask(rxDevNo, rxDev, queueNo, core)
	log:info("[Dev %d] [Queue %d] [Core %d] Rx Slave", rxDevNo, queueNo, core)
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
	log:info("[Core %d] Rx terminated after receiving %d packets", core, pkts)
end

function hwTimestampers(trxPortsNo, txDevs, rxDevs, side)
	log:info("[HW Timestampers]")

	-- Pick a packet from the correct subnet
	local src_subnet_list
	local dst_subnet_list
	if ( side == "left" ) then
		src_subnet_list = IP_SRC_LEFT
		dst_subnet_list = IP_DST_LEFT
	else
		src_subnet_list = IP_SRC_RIGHT
		dst_subnet_list = IP_DST_RIGHT
	end

	srcIP_0   = src_subnet_list[1]
	srcPort_0 = PTP_PORT_SRC
	dstIP_0   = dst_subnet_list[1]
	dstPort_0 = PTP_PORT_DST

	srcIP_1   = src_subnet_list[2]
	srcPort_1 = PTP_PORT_SRC
	dstIP_1   = dst_subnet_list[2]
	dstPort_1 = PTP_PORT_DST

	log:info("[HW Timestamper] PTP packet %s:%d --> %s:%d", srcIP_0, srcPort_0, dstIP_0, dstPort_0)
	log:info("[HW Timestamper] PTP packet %s:%d --> %s:%d", srcIP_1, srcPort_1, dstIP_1, dstPort_1)

	local txQueue0 = txDevs[1]:getTxQueue(1)
	local rxQueue0 = rxDevs[2]:getRxQueue(1)

	local txQueue1 = txDevs[2]:getTxQueue(1)
	local rxQueue1 = rxDevs[1]:getRxQueue(1)

	--local txQueue2 = txDevs[3]:getTxQueue(1)
	--local rxQueue2 = rxDevs[3]:getRxQueue(1)

	--local txQueue3 = txDevs[4]:getTxQueue(2)
	--local rxQueue3 = rxDevs[4]:getRxQueue(2)

	--rxDevs[1]:addHW5tupleFilter(
	--	{
	--		--src_ip     = parseIPAddress(srcIP_1),
	--		--dst_ip     = parseIPAddress(dstIP_1),
	--		src_port   = srcPort_1,
	--		dst_port   = dstPort_1
	--	}, 
	--	rxDevs[1]:getRxQueue(1)
	--)
	rxDevs[1]:filterTimestamps(1)

	--rxDevs[2]:addHW5tupleFilter(
	--	{
	--		--src_ip     = parseIPAddress(srcIP_0),
	--		--dst_ip     = parseIPAddress(dstIP_0),
	--		src_port   = srcPort_0,
	--		dst_port   = dstPort_0
	--	}, 
	--	rxDevs[2]:getRxQueue(1)
	--)
	rxDevs[2]:filterTimestamps(1)
	
	--rxDevs[3]:filterTimestamps(1)
	--rxDevs[4]:filterTimestamps(1)

	local timestamper0 = ts:newUdpTimestamperWithData(txQueue0, rxQueue0, srcIP_0, dstIP_0, srcPort_0, dstPort_0)
	local timestamper1 = ts:newUdpTimestamperWithData(txQueue1, rxQueue1, srcIP_1, dstIP_1, srcPort_1, dstPort_1)
	--local timestamper2 = ts:newUdpTimestamperWithData(txQueue2, rxQueue2, srcIP_2, dstIP_2, srcPort_2, dstPort_2)
	--local timestamper3 = ts:newUdpTimestamperWithData(txQueue3, rxQueue3, srcIP_3, dstIP_3, srcPort_3, dstPort_3)

	local hist0 = hist:new()
	local hist1 = hist:new()
	--local hist2 = hist:new()
	--local hist3 = hist:new()
	while moongen.running() do
		hist0:update(timestamper0:measureLatency())
		hist1:update(timestamper1:measureLatency())
	--	hist2:update(timestamper2:measureLatency())
	--	hist3:update(timestamper3:measureLatency())
	end
	log:info("[HW Timestampers] Calculating histograms]")
	hist0:save("histogram-"..side.."-p0.csv")
	hist1:save("histogram-"..side.."-p1.csv")
	--hist2:save("histogram-"..side.."-p2.csv")
	--hist3:save("histogram-"..side.."-p3.csv")
	log:info("\n")

	log:info("[HW Timestampers] Histograms saved]")
	hist0:print()
	hist1:print()
	--hist2:print()
	--hist3:print()
end

function hwTimestamper(txPort, rxPort, txQueue, rxQueue, side, subnet)
	log:info("[HW Timestamper] Tx Port %d, Rx Port %d", txPort, rxPort)

	-- Pick a packet from the correct subnet
	local src_subnet_list
	local dst_subnet_list
	if ( side == "left" ) then
		src_subnet_list = IP_SRC_LEFT
		dst_subnet_list = IP_DST_LEFT
	else
		src_subnet_list = IP_SRC_RIGHT
		dst_subnet_list = IP_DST_RIGHT
	end

	srcIP   = src_subnet_list[subnet]
	srcPort = PORT_SRC
	dstIP   = dst_subnet_list[subnet]
	dstPort = PORT_DST
	log:info("[HW Timestamper] PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local rxDev = rxQueue.dev
	rxDev:filterTimestamps(rxQueue)
	local timestamper = ts:newUdpTimestamperWithData(txQueue, rxQueue, srcIP, dstIP, srcPort, dstPort)
	local hist = hist:new()
	while moongen.running() do
		hist:update(timestamper:measureLatency())
	end

	log:info("[HW Timestamper] Calculating histogram")
	hist:save("histogram_"..side.."_"..subnet..".csv")
	log:info("\n")
	log:info("[HW Timestamper] Histogram saved")
	hist:print()
end

function printTxStats(ctr)
	local rates = {}
	rates[#rates + 1] = ctr
	stats.addStats(rates)
	local freqInGHz = 3.20
	local cyclesPerPkt = freqInGHz * 10^3 / rates.avg
	local relStdDev = rates.stdDev / rates.avg
	log:info("[Tx] Cycles/Pkt: %.2f, StdDev: %.2f", cyclesPerPkt, cyclesPerPkt * relStdDev)
end

--! @brief: A method that "manually" derives the packet rate per core
function countAndPrintThroughputPerCore(core, totalSent, lastPrint, lastTotal, pktSize)
	-- Count throughput
	local time = moongen.getTime()
	if time - lastPrint > 1 then
		local mpps = (totalSent - lastTotal) / (time - lastPrint) / 10^6
		log:info("[Core %d] Sent %d packets, current rate %.2f Mpps, %.2f MBit/s, %.2f MBit/s wire rate", 
				core, totalSent, mpps, mpps * pktSize * 8, mpps * (pktSize+20) * 8)
		lastTotal = totalSent
		lastPrint = time
	end

	return lastPrint, lastTotal
end
