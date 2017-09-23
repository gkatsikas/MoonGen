--! @file from-pcap-soft.lua
--! @brief Replay from 2 PCAP files on two ports and receive on the same ports

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

-- sudo ../../build/MoonGen from-pcap-soft.lua 2 10000000000 64 0 /home/katsikas/nfv/snf-controller/data/filter_covered/orig_acl_251_64_pcap2 /home/katsikas/nfv/snf-controller/data/filter_covered/orig_acl_251_64_pcap4 hw left

function master(trxPortsNo, rate, pktSize, maxPackets, sourcePCAP0, sourcePCAP1, timestamping, side)
	local trxPortsNo, rate, pktSize, maxPackets = tonumberall(trxPortsNo, rate, pktSize, maxPackets)
	if not trxPortsNo or not rate or not maxPackets or not pktSize or not sourcePCAP0 or not sourcePCAP1 or not side then
		return log:error([[
			Usage: trxPortsNo rate pktSize maxPackets sourcePCAP0 sourcePCAP1 timestamping side
			Timestamping = sw means software-based timestamping
			Timestamping = hw means hardware-based timestamping
			Timestamping = other value means no timestamping
		]])
	end

	local txQueuesNo = 2
	local rxQueuesNo = 2
	local txCores    = { {0}, {2}, {4}, {6} }
	local rxCores    = { {8}, {10}, {12}, {14} }

	sourcePCAP0 = sourcePCAP0
	sourcePCAP1 = sourcePCAP1
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

	trxPorts  = {0, 1}
	pcap      = {sourcePCAP0, sourcePCAP1}
	pcapSize  = {0, 0}
	udpBuf    = {}

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
	for i=1, trxPortsNo do
		local pSize = countPCAPPackets(pcap[i], pktSize, i)
		log:info("[Main] Input PCAP file %s contains %d packets", pcap[i], pSize)
		if pSize > MAX_PCAP_PKTS_NO then
			return log:error("PCAP file %s contains more than %d packets", pcap[i], MAX_PCAP_PKTS_NO)
		end
		pcapSize[i] = pSize
		udpBuf[i]   = extractUDPInfoFromPCAP(pcap[i], pktSize)
		log:info("[Main] PCAP file %s contains %d UDP packets", pcap[i], #udpBuf[i])
	end

	q = 0
	-- Tx threads on queue 0
	for i=1, #txDevs do
		--local coreOfQueue = txCores[i][math.fmod(q, #txCores) + 1]
		--log:info("[Dev %d] [Tx Queue %2d] Core: %d", txPorts[i], q, coreOfQueue)
		if ( hw_timestamping or not timestamping ) then
			moongen.startTask("pcapSendTask",       trxPorts[i], txDevs[i], q, rate, maxPackets, pktSize, pcap[i], pcapSize[i])
			--moongen.startTask("pcapSendBucketTask", txPorts[i], txDevs[i], q, rate, maxPackets, pktSize, pcap[i], pcapSize[i])
		else
			moongen.startTask("pcapSendTaskWithTS", trxPorts[i], txDevs[i], q, rate, maxPackets, pktSize, pcap[i], pcapSize[i])
		end
	end

	-- Rx threads on queue 0
	for i=1, #rxDevs do
		--local coreOfQueue = rxCores[i][1]
		--log:info("[Dev %d] [Rx Queue 0] Core: %d", rxPorts[i], coreOfQueue)
		moongen.startTask("rxCounterTask", trxPorts[i], rxDevs[i], q, sw_timestamping, side)
	end

	-- Latency calculation
	if ( hw_timestamping ) then
		--hwTimestampers(txDevs, rxDevs, udpBuf, side)
	end

	moongen.waitForTasks()
end

--! @brief: sends packets read from a PCAP file
function pcapSendTask(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	log:info("[Dev %d] Tx PCAP Thread is running", txPort)

	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)

	local batchSize = pcapSize
	if ( batchSize > 2048 ) then batchSize = 2047 end
	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	log:info("[Dev %d] PCAP Sender Thread: Allocated space for %d packets", txPort, batchSize)
	
	--real_bufs = {}
	--local real_bufs = mem:bufArray(batchSize)

	local bucketSize = 0
	local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		local rd = pcapReader:readPkt(bufs, true)
		bucketSize = bucketSize + rd
		--for i, b in ipairs(bufs) do
		--	local data = ffi.cast("uint8_t*", b.pkt.data)
		--	local pkt = b:getIPPacket()

		--	local new_b = ffi.new("struct rte_mbuf")
		--	--new_b.pkt.pkt_len  = pkt.ip4:getLength()
		--	---new_b.pkt.data_len = pkt.ip4:getLength()
		--	new_b.pool     = b.pool
		--	new_b.pkt      = b.pkt
		--	new_b.data     = b.data
		--	new_b.phy_addr = b.phy_addr
		--	new_b.len      = pkt.ip4:getLength()
		--	new_b.refcnt   = b.refcnt
		--	new_b.type     = b.type
		--	new_b.reserved = b.reserved
		--	new_b.ol_flags = b.ol_flags
		--	new_b.ol_ipsec = b.ol_ipsec

		--	real_bufs[#real_bufs+1] = new_b
		--	--ffi.copy(new_b, b, pkt.ip4:getLength())
		--	--real_bufs[#real_bufs+1] = ffi.new("struct rte_mbuf")
		--	--real_bufs[#real_bufs+1].pkt.pkt_len  = pkt.ip4:getLength()
		--	--real_bufs[#real_bufs+1].pkt.data_len = pkt.ip4:getLength()
		--	--log:info("Done")
		--	--ffi.copy(real_bufs[#real_bufs+1], b, pkt.ip4:getLength())
		--	--local new_b = ffi.new("struct rte_mbuf", pkt.ip4:getLength()+1)
		--	--ffi.copy(new_b, b, pkt.ip4:getLength())
		--	--real_buf[#real_buf + 1] = new_b
		--	--log:info("Packet size %d bytes", pkt.ip4:getLength())
		--end
		break    -- read only one big batch
	end
	log:info("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, bufs.size)

	local pkt = 1
	local ctr = stats:newDevTxCounter(txDev,"plain")
	while moongen.running() and (not maxPackets or pkt <= maxPackets) do
		--local counter = 0
		--for _, b in ipairs(bufs) do
		--	local data = ffi.cast("uint8_t*", b.pkt.data)
		--	if ( data[23] == 17 ) then
		--		local pkt = b:getUdpPacket()
		--		--log:info("UDP packet %s:%d --> %s:%d", pkt.ip4.src:getString(), pkt.udp:getSrcPort(), pkt.ip4.dst:getString(), pkt.udp:getDstPort())
		--		if ( pkt.udp:getSrcPort() == 123 and pkt.udp:getDstPort() == 2401 ) then
		--			log:info("======================================================")
		--			log:info("FOUND")
		--			log:info("======================================================")
		--		end
		--	end
		--	counter = counter + 1
		--end
		--log:info("%d packets sent", counter)

		queue:send(bufs)
		pkt = pkt + bufs.size
		
		ctr:update()
	end

	ctr:finalize()
end

--! @brief: sends packets, timestamped in software, read from a PCAP file
function pcapSendTaskWithTS(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	log:info("[Dev %d] Tx PCAP Timestamper is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)

	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(pcapSize)
	bufs:alloc(pktSize)
	local bucketSize = 0
	local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done do
		local rd = pcapReader:readPkt(bufs, true)
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

function rxCounterTask(rxDevNo, rxDev, queueNo, timestamping, side)
	log:info("[Dev %d] Rx Task", rxDevNo)
	local queue = rxDev:getRxQueue(queueNo)

	local tscFreq    = moongen.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs       = memory.bufArray(64)  -- 64
	if ( timestamping ) then
		log:info("Rx is filtering timestamps")
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
		bufs:free(numPkts)
		--bufs:freeAll()
		
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

function hwTimestampers(txDevs, rxDevs, udpBuf, side)
	log:info("[HW Timestampers]")

	-- Pick a random index
	srcIP   = udpBuf[1][2][1]
	srcPort = udpBuf[1][2][2]
	dstIP   = udpBuf[1][2][3]
	dstPort = udpBuf[1][2][4]
	dstPort = 123
	log:info("PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local txQueue0 = txDevs[1]:getTxQueue(1)
	local rxQueue0 = rxDevs[1]:getRxQueue(1)
	--rxDevs[1]:addHW5tupleFilter(
	--	{
	--		src_ip     = parseIPAddress(srcIP),
	--		dst_ip     = parseIPAddress(dstIP),
	--		src_port   = srcPort,
	--		dst_port   = dstPort
	--	}, 
	--	rxDevs[1]:getRxQueue(1)
	--)
	rxDevs[1]:filterTimestamps(1)
	local timestamper0 = ts:newUdpTimestamperWithData(txQueue0, rxQueue0, srcIP, dstIP, srcPort, dstPort)

	-- Pick a random index
	srcIP   = udpBuf[2][2][1]
	srcPort = udpBuf[2][2][2]
	dstIP   = udpBuf[2][2][3]
	dstPort = udpBuf[2][2][4]
	dstPort = 123
	log:info("PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local txQueue1 = txDevs[2]:getTxQueue(1)
	local rxQueue1 = rxDevs[2]:getRxQueue(1)
	rxDevs[2]:filterTimestamps(1)
	local timestamper1 = ts:newUdpTimestamperWithData(txQueue1, rxQueue1, srcIP, dstIP, srcPort, dstPort)

	local hist0 = hist:new()
	local hist1 = hist:new()
	while moongen.running() do
		hist0:update(timestamper0:measureLatency())
		hist1:update(timestamper1:measureLatency())
	end
	log:info("[HW Timestampers] Calculating histograms]")
	hist0:save("latency-"..side.."-dev0.txt")
	hist1:save("latency-"..side.."-dev1.txt")
	log:info("\n")

	log:info("[HW Timestampers] Histograms saved]")
	hist0:print()
	hist1:print()
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
		local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
		while not pcapReader.done do
			local rd = pcapReader:readPkt(bufs, true)
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
function countPCAPPackets(sourcePCAP, pktSize, port)
	local pktCounter = 0
	local mem        = memory.createMemPool()
	local buf        = mem:bufArray(1)
	buf:alloc(pktSize)
	local pcapReader = pcapReader:newPcapReader(sourcePCAP)

	--local f = io.open("trace-"..port..".txt", "w+")

	while not pcapReader.done do
		local rd   = pcapReader:readPkt(buf, true)
		pktCounter = pktCounter + rd
		--for _, b in ipairs(buf) do
		--	local data = ffi.cast("uint8_t*", b.pkt.data)

		--	-- UDP packet
		--	if ( data[23] == 17 ) then
		--		local pkt = b:getUdpPacket()
		--		--log:info("UDP packet %s:%d --> %s:%d", pkt.ip4.src:getString(), pkt.udp:getSrcPort(), pkt.ip4.dst:getString(), pkt.udp:getDstPort())
		--		f:write("Proto ".. pkt.ip4.protocol.."    "..pkt.ip4.src:getString()..":"..pkt.udp:getSrcPort().." --> "..pkt.ip4.dst:getString()..":"..pkt.udp:getDstPort().."\n")

		--		if ( pkt.udp:getSrcPort() == 123 and pkt.udp:getDstPort() == 2401 ) then
		--			log:info("======================================================")
		--			log:info("FOUND")
		--			log:info("======================================================")
		--		end
		--	end
		--	break
		--end
	end

	--f:close()
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

				if ( pkt.udp.src == 123 and pkt.udp.dst == 2401 ) then
					log:info("======================================================")
					log:info("FOUND")
					log:info("======================================================")
				end
			end
			break
		end

		pktCounter = pktCounter + rd
	end
	buf:freeAll()

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
function pcapSendBucketTask(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	log:info("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)
	
	local batchSize = 255
	local bufs_no   = 8 --math.ceil(pcapSize / batchSize)
	log:info("[Dev %d] PCAP Sender Thread: Prepared %d buckets", txPort, bufs_no)
	local mem  = memory.createMemPool()
	local bufs = {}
	for i=1, bufs_no do
		bufs[i] = mem:bufArray(batchSize)
		bufs[i]:alloc(pktSize)
	end
	log:info("[Dev %d] PCAP Sender Thread: Allocated %d bufs each at the size of %d packets", txPort, bufs_no, batchSize)
	
	local pkt        = 1
	local bucketSize = 0
	local currBucket = 1
	local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		if ( bucketSize >= batchSize ) then
			bucketSize = 0
			currBucket = currBucket + 1
		end
		local rd = pcapReader:readPkt(bufs[currBucket], true)
		bucketSize = bucketSize + rd
		pkt = pkt + rd

		if ( currBucket == bufs_no ) then currBucket =1 end
	end
	log:info("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, pkt)

	local ctr = stats:newDevTxCounter(txDev,"plain")

	local pkt = 1
	while moongen.running() and (not maxPackets or pkt <= maxPackets) do
		for i=1, bufs_no do
			queue:send(bufs[i])
			pkt = pkt + bufs[i].size
			ctr:update()
		end
	end

	ctr:finalize()
end
