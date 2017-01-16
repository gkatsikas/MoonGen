--! @file trx-from-pcap.lua
--! @brief Replay from PCAP on a specific port and receive on another port

local moongen = require "moongen"
local memory  = require "memory"
local device  = require "device"
local log     = require "log"
local ts      = require "timestamping"
local pcap    = require "pcap"
local stats   = require "stats"
local hist    = require "histogram"
local ffi     = require "ffi"

local MAX_PCAP_PKTS_NO = 2048

-- sudo ../../build/MoonGen trx-from-pcap.lua 0 1 10000000000 64 0 /home/katsikas/nfv/snf-controller/data/original/acl_251_compressed.pcap

function master(txPort, rxPort, rate, pktSize, maxPackets, sourcePCAP)
	local txPort, rxPort, rate, pktSize, maxPackets = tonumberall(txPort, rxPort, rate, pktSize, maxPackets)
	if not txPort or not rxPort or not rate or not maxPackets or not pktSize or not sourcePCAP then
		return log:error("Usage: txPort rxPort rate pktSize maxPackets sourcePCAP")
	end

	local txQueuesNo = 2
	local rxQueuesNo = 2

	sourcePCAP = sourcePCAP
	if maxPackets == 0 then maxPackets = nil end

	local txDev, rxDev
	if ( txPort == rxPort  ) then
		txDev = device.config{ port=txPort, txQueues=txQueuesNo, rxQueues=rxQueuesNo }
		rxDev = txDev
	else
		txDev = device.config{ port=txPort, txQueues=txQueuesNo }
		rxDev = device.config{ port=rxPort, rxQueues=rxQueuesNo }
	end
	moongen.sleepMillis(100)

	-- Find how many packets there are in the input pcap file
	local pcapSize = countPCAPPackets(sourcePCAP, pktSize)
	log:info("[Main] Input PCAP file contains %d packets", pcapSize)
	if pcapSize > MAX_PCAP_PKTS_NO then
		return log:error("PCAP file contains more than %d packets", MAX_PCAP_PKTS_NO)
	end

	udpBuf = extractUDPInfoFromPCAP(sourcePCAP, pktSize)
	log:info("[Main] PCAP file contains %d UDP packets", #udpBuf)

	-- Load the trace in memory
	--bufs = laodPCAPPackets(sourcePCAP, pktSize, pcapSize)
	--log:info("[Main] PCAP file contains %d packets", bufs.size)

	moongen.startTask("pcapSendTask",  txPort, txDev, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	moongen.startTask("rxCounterTask", rxPort, rxDev)
	hwTimestamper(txPort, rxPort, txDev:getTxQueue(1), rxDev:getRxQueue(1), udpBuf)
	moongen.waitForTasks()
end

--! @brief: sends the pcap contents out
function pcapSendTask(txPort, txDev, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	log:info("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(0)
	queue:setRate(rate)

	local batchSize = pcapSize
	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	log:info("[Dev %d] PCAP Sender Thread: Allocated space for %d packets", txPort, batchSize)
	
	local bucketSize = 0
	local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		local rd = pcapReader:readPkt(bufs, true)
		bucketSize = bucketSize + rd
	end
	log:info("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, bufs.size)

	local pkt = 1
	local ctr = stats:newDevTxCounter(txDev,"plain")
	while moongen.running() and (not maxPackets or pkt <= maxPackets) do
		queue:send(bufs)
		pkt = pkt + bufs.size
		ctr:update()
	end

	ctr:finalize()
end

function rxCounterTask(rxDevNo, rxDev)
	local queue = rxDev:getRxQueue(0)
	log:info("[Dev %d] Rx Slave", rxDevNo)
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
	log:info("[Dev %d] Rx terminated after receiving %d packets", rxDevNo, pkts)
end

function hwTimestamper(txPort, rxPort, txQueue, rxQueue, udpBuf)
	log:info("[HW Timestamper] Tx Port %d, Rx Port %d", txPort, rxPort)

	-- Pick a random index
	srcIP   = udpBuf[14][1]
	srcPort = udpBuf[14][2]
	dstIP   = udpBuf[14][3]
	dstPort = udpBuf[14][4]
	dstPort = 123
	log:info("[HW Timestamper] PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local rxDev = rxQueue.dev
	rxDev:filterTimestamps(rxQueue)
	--local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	local timestamper = ts:newUdpTimestamperWithData(txQueue, rxQueue, srcIP, dstIP, srcPort, dstPort)
	local hist = hist:new()
	while moongen.running() do
		hist:update(timestamper:measureLatency())
	end
	log:info("[HW Timestamper] Calculating histogram")
	hist:save("histogram.csv")
	log:info("\n")
	log:info("[HW Timestamper] Histogram saved")
	hist:print()
end

--! @brief: Counts the number of packets in a PCAP file.
function countPCAPPackets(sourcePCAP, pktSize)
	local pktCounter = 0
	local mem        = memory.createMemPool()
	local buf        = mem:bufArray(1)
	buf:alloc(pktSize)
	local pcapReader = pcapReader:newPcapReader(sourcePCAP)
	while not pcapReader.done do
		local rd   = pcapReader:readPkt(buf, true)
		pktCounter = pktCounter + rd
	end

	buf:freeAll()

	return pktCounter
end

--! @brief: Load the content of a PCAP file into memory.
function laodPCAPPackets(sourcePCAP, pktSize, pcapSize)
	batchSize = pcapSize
	mem  = memory.createMemPool()
	bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	log:info("[PCAP Loader] Allocated space for %d packets", batchSize)
	
	bucketSize = 0
	pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (bucketSize <= batchSize) do
		local rd = pcapReader:readPkt(bufs, true)
		bucketSize = bucketSize + rd
	end
	log:info("[PCAP Loader] Loaded %d packets in memory", bufs.size)

	return bufs
end

--! @brief: Counts the number of packets in a PCAP file.
function extractUDPInfoFromPCAP(sourcePCAP, pktSize)

	local pktCounter = 0
	local mem        = memory.createMemPool()
	local buf        = mem:bufArray(1)
	buf:alloc(pktSize)
	local udpBuf     = {}

	local udpCounter = 1

	local pcapReader = pcapReader:newPcapReader(sourcePCAP)
	while not pcapReader.done do
		local rd = pcapReader:readPkt(buf, true)

		-- Inspect the packet
		for _, b in ipairs(buf) do
			local data = ffi.cast("uint8_t*", b.pkt.data)

			-- UDP packet
			if ( data[23] == 17 ) then
				local pkt = b:getUdpPacket()
				--log:info("UDP packet %s:%d --> %s:%d", pkt.ip4.src:getString(), pkt.udp.src, pkt.ip4.dst:getString(), pkt.udp.dst)
				udpBuf[#udpBuf+1] = {pkt.ip4.src:getString(), pkt.udp.src, pkt.ip4.dst:getString(), pkt.udp.dst}
				udpCounter = udpCounter + 1
			end
			break
		end

		pktCounter = pktCounter + rd
	end
	buf:freeAll()
	--log:info("------------------------------------------------------")

	return udpBuf
end

function deepcopy(orig)
	local orig_type = type(orig)
	local copy
	if orig_type == 'table' then
		copy = {}
		for orig_key, orig_value in next, orig, nil do
			copy[deepcopy(orig_key)] = deepcopy(orig_value)
		end
		setmetatable(copy, deepcopy(getmetatable(orig)))
	else -- number, string, boolean, etc
		copy = orig
	end
	return copy
end

--! @brief: sends a packet out
function pcapSendBucketTask(txPort, txDev, rate, pktSize, maxPackets, pcapSize, sourcePCAP)
	log:info("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(0)
	queue:setRate(rate)
	
	local bufs_no   = 8
	local batchSize = 255
	local mem  = memory.createMemPool()
	local bufs = {}
	for i = 0, bufs_no-1 do
		bufs[i] = mem:bufArray(batchSize)
		bufs[i]:alloc(pktSize)
	end
	log:info("[Dev %d] PCAP Sender Thread: Allocated %d bufs each at the size of %d packets", txPort, bufs_no, batchSize)
	
	local pkt        = 1
	local bucketSize = 0
	local currBucket = 0
	local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		if ( bucketSize >= batchSize ) then
			bucketSize = 0
			currBucket = currBucket + 1
		end
		local rd = pcapReader:readPkt(bufs[currBucket], true)
		bucketSize = bucketSize + rd
		pkt = pkt + rd
	end
	log:info("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, pkt)

	local ctr = stats:newDevTxCounter(txDev,"plain")

	local pkt = 1
	while moongen.running() and (not maxPackets or pkt <= maxPackets) do
		for i = 0, bufs_no-1 do
			queue:send(bufs[i])
			pkt = pkt + bufs[i].size
			ctr:update()
		end
	end

	ctr:finalize()
end
