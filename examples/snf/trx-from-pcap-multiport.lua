--! @file tx-from-pcap.lua
--! @brief Replay from PCAP on multiple ports and receive on other ports

local moongen = require "moongen"
local memory  = require "memory"
local device  = require "device"
local log     = require "log"
local ts      = require "timestamping"
local pcap    = require "pcap"
local stats   = require "stats"
local hist    = require "histogram"
local ffi     = require "ffi"

local MAX_PCAP_PKTS_NO = 4228  -- 2048

-- sudo ../../build/MoonGen trx-from-pcap-multiport.lua 2 10000000000 64 0 /home/katsikas/nfv/snf-controller/data/original/acl_251_compressed.pcap sw left

function master(trxPortsNo, rate, pktSize, maxPackets, sourcePCAP, timestamping, side)
	local trxPortsNo, rate, pktSize, maxPackets = tonumberall(trxPortsNo, rate, pktSize, maxPackets)
	if not trxPortsNo or not rate or not maxPackets or not pktSize or not sourcePCAP or not side then
		return log:error([[
			Usage: trxPortsNo rate pktSize maxPackets sourcePCAP timestamping side
			Timestamping = sw means software-based timestamping
			Timestamping = hw means hardware-based timestamping
			Timestamping = other value means no timestamping
		]])
	end

	local txQueuesNo = 2
	local rxQueuesNo = 2
	local txCores    = { {2}, {4}, {6}, {8} }
	local rxCores    = { {10}, {12}, {14}, {14} }

	sourcePCAP = sourcePCAP
	if maxPackets == 0 then maxPackets = nil end

	sw_timestamping = false
	hw_timestamping = false
	if (timestamping == "sw" ) then
		timestamping    = true
		sw_timestamping = true
	elseif ( timestamping == "hw" ) then
		timestamping    = true
		hw_timestamping = true
	else
		timestamping = false
	end

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
	moongen.sleepMillis(100)

	-- Find how many packets there are in the input pcap file
	local pcapSize = countPCAPPackets(sourcePCAP, pktSize)
	log:info("[Main] Input PCAP file contains %d packets", pcapSize)
	if pcapSize > MAX_PCAP_PKTS_NO then
		return log:info([[PCAP file contains more than %d packets]], MAX_PCAP_PKTS_NO)
	end

	udpBuf = extractUDPInfoFromPCAP(sourcePCAP, pktSize)
	log:info("[Main] PCAP file contains %d UDP packets", #udpBuf)

	q = 0
	-- Tx threads on queue 0
	for i=0, #txDevs-1 do
		--local coreOfQueue = txCores[i+1][math.fmod(q, #txCores) + 1]
		--log:info("[Dev %d] [Tx Queue %d] Core: %d", i, q, coreOfQueue)
		if ( hw_timestamping or not timestamping ) then
			moongen.startTask("pcapSendSlave",       i, txDevs[i+1], q, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
		else
			moongen.launchLua("pcapSendSlaveWithTS", i, txDevs[i+1], q, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
		end
	end

	-- Rx threads on queue 0
	for i = 0, #rxDevs-1 do
		--local coreOfQueue = rxCores[i+1][1]
		--log:info("[Dev %d] [Rx Queue 0] Core: %d", i, coreOfQueue)
		moongen.startTask("rxCounterSlave", i, rxDevs[i+1], q, sw_timestamping, side)
	end

	-- Latency calculation
	if ( hw_timestamping ) then
		--hwTimestampers(trxPortsNo, txDevs, rxDevs, udpBuf, side)
	end

	moongen.waitForTasks()
end

--! @brief: sends packets read from a PCAP file
function pcapSendSlave(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	log:info("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)

	local batchSize = pcapSize
	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	log:info("[Dev %d] PCAP Sender Thread: Allocated space for %d packets", txPort, batchSize)
	
	local bucketSize = 0
	local pcapReader = pcap:newReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		local rd = pcapReader:read(bufs)
		bucketSize = bucketSize + rd
		break
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

--! @brief: sends packets, timestamped in software, read from a PCAP file
function pcapSendSlaveWithTS(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	log:info("[Dev %d] Tx PCAP Timestamper is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)

	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(pcapSize)
	bufs:alloc(pktSize)
	local bucketSize = 0
	local pcapReader = pcap:newReader(sourcePCAP, 10000)
	while not pcapReader.done do
		local rd = pcapReader:read(bufs, true)
		bucketSize = bucketSize + rd
	end
	log:info("[Dev %d] Tx PCAP Timestamper: Loaded %d packets in memory", txPort, bufs.size)
	
	local pkt = 0
	local index = 2
	local ctr = stats:newDevTxCounter(txDev,"plain")
	while moongen.running() and (not maxPackets or pkt <= maxPackets) do
		-- sendWithTimestamp method can only send the first packet of the buffer
		-- We shuffle the first position of this buffer in every iteration
		if (index > bufs.size) then index = 2 end
		temp = bufs[1]
		bufs[1] = bufs[index]
		--bufs[1], bufs[index] = bufs[index], bufs[1]
		queue:sendWithTimestamp(bufs)
		--bufs[1], bufs[index] = bufs[index], bufs[1]
		bufs[1] = temp
		index = index + 1

		pkt = pkt + bucketSize
		ctr:update()
	end
	bufs:freeAll()
	ctr:finalize()
end

function rxCounterSlave(rxDevNo, rxDev, queueNo, timestamping, side)
	log:info("[Dev %d] Rx Slave", rxDevNo)
	local queue = rxDev:getRxQueue(queueNo)

	local tscFreq    = moongen.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs       = memory.bufArray() -- 64
	if ( timestamping ) then
		queue.dev:filterTimestamps(queue)
	end
	local rxts    = {}
	local results = {}
		
	local ctr   = stats:newDevRxCounter(rxDev, "plain")
	local pkts  = 0
	while moongen.running() do
		local numPkts
		if ( timestamping ) then
			numPkts = queue:recvWithTimestamps(bufs, timestamps)
			for i = 1, numPkts do
				local rxTs = timestamps[i - 1]
				local txTs = bufs[i]:getSoftwareTxTimestamp()
				results[#results + 1] = tonumber(rxTs - txTs) / tscFreq * 10^9 -- to nanoseconds
				rxts[#rxts + 1] = tonumber(rxTs)
			end
		else
			numPkts = queue:recv(bufs)
		end
		--bufs:free(numPkts)
		bufs:freeAll()
		
		pkts = pkts + numPkts
		ctr:update()
	end
	ctr:finalize()

	if ( timestamping ) then
		lat_file = "latency-"..side.."-dev"..rxDevNo..".txt"
		log:info("[PCAP Rx Timestamper] Dumping latency to %s", lat_file)
		local f = io.open(lat_file, "w+")
		for i, v in ipairs(results) do
			f:write(v .. "\n")
		end
		f:close()
	end

	log:info("[Dev %d] Rx terminated after receiving %d packets", rxDevNo, pkts)
end

function hwTimestampers(trxPortsNo, txDevs, rxDevs, udpBuf, side)
	log:info("[HW Timestampers]")

	-- Pick a random index
	srcIP   = udpBuf[14][1]
	srcPort = udpBuf[14][2]
	dstIP   = udpBuf[14][3]
	dstPort = udpBuf[14][4]
	dstPort = 123
	log:info("PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local txQueue0 = txDevs[1]:getTxQueue(1)
	local rxQueue0 = rxDevs[2]:getRxQueue(1)

	local txQueue1 = txDevs[2]:getTxQueue(1)
	local rxQueue1 = rxDevs[1]:getRxQueue(1)

	--local txQueue2 = txDevs[3]:getTxQueue(1)
	--local rxQueue2 = rxDevs[4]:getRxQueue(1)

	--local txQueue3 = txDevs[4]:getTxQueue(1)
	--local rxQueue3 = rxDevs[3]:getRxQueue(1)

	rxDevs[1]:filterTimestamps(1)
	rxDevs[2]:filterTimestamps(1)
	--rxDevs[3]:filterTimestamps(1)
	--rxDevs[4]:filterTimestamps(1)

	local timestamper0 = ts:newUdpTimestamperWithData(txQueue0, rxQueue0, srcIP, dstIP, srcPort, dstPort)
	local timestamper1 = ts:newUdpTimestamperWithData(txQueue1, rxQueue1, srcIP, dstIP, srcPort, dstPort)
	--local timestamper2 = ts:newUdpTimestamperWithData(txQueue2, rxQueue2, srcIP, dstIP, srcPort, dstPort)
	--local timestamper3 = ts:newUdpTimestamperWithData(txQueue3, rxQueue3, srcIP, dstIP, srcPort, dstPort)

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
	hist0:save("latency-"..side.."-dev0.txt")
	hist1:save("latency-"..side.."-dev1.txt")
	--hist2:save("histogram-"..side.."-p2.txt")
	--hist3:save("histogram-"..side.."-p3.txt")
	log:info("\n")

	log:info("[HW Timestampers] Histograms saved]")
	hist0:print()
	hist1:print()
	--hist2:print()
	--hist3:print()
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

function txTimestamper(queue, pktSize, sourcePCAP, pcapSize)
	local mem = memory.createMemPool(function(buf)
		-- just to use the default filter here
		-- you can use whatever packet type you want
		buf:getUdpPtpPacket():fill{
		}
	end)
	local bufs = mem:bufArray(1)
	bufs:alloc(pktSize)

	local total_pkts = 0
	while moongen.running() do
		local bucketSize = 0
		local pcapReader = pcap:newReader(sourcePCAP, 10000)
		while not pcapReader.done do
			local rd = pcapReader:read(bufs, true)
			bucketSize = bucketSize + rd
			queue:sendWithTimestamp(bufs)
		end
		total_pkts = total_pkts + bucketSize
		--log:info("[PCAP Tx Timestamper] Sent %d packets", bucketSize)
	end
	log:info("[PCAP Tx Timestamper] Sent %d packets", total_pkts)
	moongen.sleepMillis(500)
	moongen.stop()
end

function rxTimestamper(queue, pktSize)
	local tscFreq    = moongen.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs       = memory.bufArray(64)
	queue.dev:filterTimestamps(queue)

	log:info("[PCAP Rx Timestamper] Starts")

	local rxts    = {}
	local results = {}
	while moongen.running() do
		local numPkts = queue:recvWithTimestamps(bufs, timestamps)
		log:info("[PCAP Rx Timestamper] Received %d packets", numPkts)
		for i = 1, numPkts do
			local rxTs = timestamps[i - 1]
			local txTs = bufs[i]:getSoftwareTxTimestamp()
			results[#results + 1] = tonumber(rxTs - txTs) / tscFreq * 10^9 -- to nanoseconds
			rxts      [#rxts + 1] = tonumber(rxTs)
		end
		
		bufs:free(numPkts)
	end
	lat_file = "latency.txt"
	log:info("[PCAP Rx Timestamper] Dumping latency to %s", lat_file)
	local f = io.open(lat_file, "w+")
	for i, v in ipairs(results) do
		log:info("\t%f", v)
		f:write(v .. "\n")
	end
	f:close()
end

--! @brief: Counts the number of packets in a PCAP file.
function countPCAPPackets(sourcePCAP, pktSize)
	local pktCounter = 0
	local mem        = memory.createMemPool()
	local buf        = mem:bufArray(1)
	buf:alloc(pktSize)
	local pcapReader = pcap:newReader(sourcePCAP)
	while not pcapReader.done do
		local rd   = pcapReader:read(buf, true)
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
	pcapReader = pcap:newReader(sourcePCAP, 10000)
	while not pcapReader.done and (bucketSize <= batchSize) do
		local rd = pcapReader:read(bufs, true)
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

	local pcapReader = pcap:newReader(sourcePCAP)
	while not pcapReader.done do
		local rd = pcapReader:read(buf, true)

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
function pcapSendBucketSlave(txPort, txDev, rate, pktSize, maxPackets, pcapSize, sourcePCAP)
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
	local pcapReader = pcap:newReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		if ( bucketSize >= batchSize ) then
			bucketSize = 0
			currBucket = currBucket + 1
		end
		local rd = pcapReader:read(bufs[currBucket], true)
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
