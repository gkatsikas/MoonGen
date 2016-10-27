--! @file from-pcap-noviflow.lua
--! @brief Replay from 2 PCAP files on two ports and receive on two other ports

local mg	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local log	= require "log"
local ts 	= require "timestamping"
local pcap	= require "pcap"
local stats	= require "stats"
local hist	= require "histogram"
local ffi	= require "ffi"

local ETH_HEADER_LENGHT = 14
local MAX_PCAP_PKTS_NO  = 4228  -- 2048

-- sudo ../../build/MoonGen from-pcap-noviflow.lua 2 10000000000 0 /home/katsikas/nfv/snf-controller/data/filter_covered_new/orig_acl_251_64_pcap2 /home/katsikas/nfv/snf-controller/data/filter_covered_new/orig_acl_251_64_pcap4 hw left

function master(trxPortsNo, rate, maxPackets, sourcePCAP0, sourcePCAP1, timestamping, side)
	local trxPortsNo, rate, maxPackets = tonumberall(trxPortsNo, rate, maxPackets)
	if not trxPortsNo or not rate or not maxPackets or not sourcePCAP0 or not sourcePCAP1 or not side then
		return log:info([[
			Usage: trxPortsNo rate maxPackets sourcePCAP0 sourcePCAP1 timestamping side
			Timestamping = sw means software-based timestamping
			Timestamping = hw means hardware-based timestamping
			Timestamping = other value means no timestamping
		]])
	end

	local txQueuesNo = 2
	local rxQueuesNo = 2
	local txCores    = { {2}, {4}, {6}, {8} }
	local rxCores    = { {10}, {12}, {14}, {14} }

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

	txPortsNo = 2
	rxPortsNo = trxPortsNo

	if ( txPortsNo == 1 ) then
		txPorts = {0}
	else
		txPorts = {0, 1}
	end
	if ( rxPortsNo == 1 ) then
		rxPorts = {2}
	else
		rxPorts = {2, 3}
	end
	pcap      = {sourcePCAP0, sourcePCAP1}
	pcapSize  = {0, 0}
	udpBuf    = {}

	-- Configure each device for Tx
	local txDevs = {}
	local rxDevs = {}
	for i=1, txPortsNo do
		txDevs[#txDevs+1] = device.config{ port=txPorts[i], txQueues=txQueuesNo }
	end
	for i=1, rxPortsNo do
		rxDevs[#rxDevs+1] = device.config{ port=rxPorts[i], rxQueues=rxQueuesNo }
	end
	-- Wait until the links are up
	device.waitForLinks()
	mg.sleepMillis(100)

	local pktsNo  = 0
	local pktSize = 0

	-- Find how many packets there are in the input pcap file
	for i=1, txPortsNo do
		pktsNo, pktSize = countPCAPPackets(pcap[i], i)
		printf("[Main] Input PCAP file %s contains %d packets of size %d", pcap[i], pktsNo, pktSize)
		if pktsNo > MAX_PCAP_PKTS_NO then
			return log:info([[PCAP file %s contains more than %d packets]], pcap[i], MAX_PCAP_PKTS_NO)
		end
		pcapSize[i] = pktsNo
		udpBuf[i]   = extractUDPInfoFromPCAP(pcap[i], pktSize)
		printf("[Main] PCAP file %s contains %d UDP packets", pcap[i], #udpBuf[i])
	end

	q = 0
	-- Tx threads on queue 0
	for i=1, #txDevs do
		--local coreOfQueue = txCores[i][math.fmod(q, #txCores) + 1]
		--printf("[Dev %d] [Tx Queue %d] Core: %d", txPorts[i], q, coreOfQueue)
		if ( hw_timestamping or not timestamping ) then
			mg.launchLua("pcapSendSlave",       txPorts[i], txDevs[i], q, rate, maxPackets, pktSize, pcap[i], pcapSize[i])
			--mg.launchLua("pcapSendBucketSlave", txPorts[i], txDevs[i], q, rate, maxPackets, pktSize, pcap[i], pcapSize[i])
		else
			mg.launchLua("pcapSendSlaveWithTS", txPorts[i], txDevs[i], q, rate, maxPackets, pktSize, pcap[i], pcapSize[i])
		end
	end

	-- Rx threads on queue 0
	for i=1, #rxDevs do
		--local coreOfQueue = rxCores[i][1]
		--printf("[Dev %d] [Rx Queue 0] Core: %d", rxPorts[i], coreOfQueue)
		mg.launchLua("rxCounterSlave", rxPorts[i], rxDevs[i], q, sw_timestamping, side)
	end

	-- Latency calculation
	if ( hw_timestamping ) then
		--hwTimestampers(txDevs, rxDevs, udpBuf, side)
	end

	mg.waitForSlaves()
end

--! @brief: sends packets read from a PCAP file
function pcapSendSlave(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	printf("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)

	local batchSize = pcapSize
	if ( batchSize > 2048 ) then batchSize = 2047 end
	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	printf("[Dev %d] PCAP Sender Thread: Allocated space for %d packets", txPort, batchSize)
	
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
		--	--printf("Done")
		--	--ffi.copy(real_bufs[#real_bufs+1], b, pkt.ip4:getLength())
		--	--local new_b = ffi.new("struct rte_mbuf", pkt.ip4:getLength()+1)
		--	--ffi.copy(new_b, b, pkt.ip4:getLength())
		--	--real_buf[#real_buf + 1] = new_b
		--	--printf("Packet size %d bytes", pkt.ip4:getLength())
		--end
		break    -- read only one big batch
	end
	printf("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, bufs.size)

	local pkt = 1
	local ctr = stats:newDevTxCounter(txDev,"plain")
	while mg.running() and (not maxPackets or pkt <= maxPackets) do
		--local counter = 0
		--for _, b in ipairs(bufs) do
		--	local data = ffi.cast("uint8_t*", b.pkt.data)
		--	if ( data[23] == 17 ) then
		--		local pkt = b:getUdpPacket()
		--		--printf("UDP packet %s:%d --> %s:%d", pkt.ip4.src:getString(), pkt.udp:getSrcPort(), pkt.ip4.dst:getString(), pkt.udp:getDstPort())
		--		if ( pkt.udp:getSrcPort() == 123 and pkt.udp:getDstPort() == 2401 ) then
		--			printf("======================================================")
		--			printf("FOUND")
		--			printf("======================================================")
		--		end
		--	end
		--	counter = counter + 1
		--end
		--printf("%d packets sent", counter)

		queue:send(bufs)
		pkt = pkt + bufs.size
		
		ctr:update()
	end

	ctr:finalize()
end

--! @brief: sends packets, timestamped in software, read from a PCAP file
function pcapSendSlaveWithTS(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	printf("[Dev %d] Tx PCAP Timestamper is running", txPort)
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
	printf("[Dev %d] Tx PCAP Timestamper: Loaded %d packets in memory", txPort, bufs.size)
	
	local pkt = 0
	local index = 2
	local ctr = stats:newDevTxCounter(txDev,"plain")
	while mg.running() and (not maxPackets or pkt <= maxPackets) do
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
	printf("[Dev %d] Rx Slave", rxDevNo)
	local queue = rxDev:getRxQueue(queueNo)

	local tscFreq    = mg.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs       = memory.bufArray(64)  -- 64
	if ( timestamping ) then
		printf("Rx is filtering timestamps")
		queue.dev:filterTimestamps(queue)
	end
	local rxts    = {}
	local results = {}
		
	local ctr   = stats:newDevRxCounter(rxDev, "plain")
	local pkts  = 0
	while mg.running() do
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
		printf("[PCAP Rx Timestamper] Dumping latency to %s", lat_file)
		local f = io.open(lat_file, "w+")
		for i, v in ipairs(results) do
			f:write(v .. "\n")
		end
		f:close()
	end

	printf("[Dev %d] Rx terminated after receiving %d packets", rxDevNo, pkts)
end

function hwTimestampers(txDevs, rxDevs, udpBuf, side)
	printf("[HW Timestampers]")

	-- Pick a random index
	srcIP   = udpBuf[1][2][1]
	srcPort = udpBuf[1][2][2]
	dstIP   = udpBuf[1][2][3]
	dstPort = udpBuf[1][2][4]
	dstPort = 123
	printf("PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

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
	printf("PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local txQueue1 = txDevs[2]:getTxQueue(1)
	local rxQueue1 = rxDevs[2]:getRxQueue(1)
	rxDevs[2]:filterTimestamps(1)
	local timestamper1 = ts:newUdpTimestamperWithData(txQueue1, rxQueue1, srcIP, dstIP, srcPort, dstPort)

	local hist0 = hist:new()
	local hist1 = hist:new()
	while mg.running() do
		hist0:update(timestamper0:measureLatency())
		hist1:update(timestamper1:measureLatency())
	end
	printf("[HW Timestampers] Calculating histograms]")
	hist0:save("latency-"..side.."-dev0.txt")
	hist1:save("latency-"..side.."-dev1.txt")
	printf("\n")

	printf("[HW Timestampers] Histograms saved]")
	hist0:print()
	hist1:print()
end

function hwTimestamper(txPort, rxPort, txQueue, rxQueue, udpBuf)
	printf("[HW Timestamper] Tx Port %d, Rx Port %d", txPort, rxPort)

	-- Pick a random index
	srcIP   = udpBuf[14][1]
	srcPort = udpBuf[14][2]
	dstIP   = udpBuf[14][3]
	dstPort = udpBuf[14][4]
	dstPort = 123
	printf("[HW Timestamper] PTP packet %s:%d --> %s:%d", srcIP, srcPort, dstIP, dstPort)

	local rxDev = rxQueue.dev
	rxDev:filterTimestamps(rxQueue)
	--local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	local timestamper = ts:newUdpTimestamperWithData(txQueue, rxQueue, srcIP, dstIP, srcPort, dstPort)
	local hist = hist:new()
	while mg.running() do
		hist:update(timestamper:measureLatency())
	end
	printf("[HW Timestamper] Calculating histogram")
	hist:save("histogram.csv")
	printf("\n")
	printf("[HW Timestamper] Histogram saved")
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
	while mg.running() do
		local bucketSize = 0
		local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
		while not pcapReader.done do
			local rd = pcapReader:readPkt(bufs, true)
			bucketSize = bucketSize + rd
			queue:sendWithTimestamp(bufs)
		end
		total_pkts = total_pkts + bucketSize
		--printf("[PCAP Tx Timestamper] Sent %d packets", bucketSize)
	end
	printf("[PCAP Tx Timestamper] Sent %d packets", total_pkts)
	mg.sleepMillis(500)
	mg.stop()
end

function rxTimestamper(queue, pktSize)
	local tscFreq    = mg.getCyclesFrequency()
	local timestamps = ffi.new("uint64_t[64]")
	local bufs       = memory.bufArray(64)
	queue.dev:filterTimestamps(queue)

	printf("[PCAP Rx Timestamper] Starts")

	local rxts    = {}
	local results = {}
	while mg.running() do
		local numPkts = queue:recvWithTimestamps(bufs, timestamps)
		printf("[PCAP Rx Timestamper] Received %d packets", numPkts)
		for i = 1, numPkts do
			local rxTs = timestamps[i - 1]
			local txTs = bufs[i]:getSoftwareTxTimestamp()
			results[#results + 1] = tonumber(rxTs - txTs) / tscFreq * 10^9 -- to nanoseconds
			rxts      [#rxts + 1] = tonumber(rxTs)
		end
		
		bufs:free(numPkts)
	end
	lat_file = "latency.txt"
	printf("[PCAP Rx Timestamper] Dumping latency to %s", lat_file)
	local f = io.open(lat_file, "w+")
	for i, v in ipairs(results) do
		printf("\t%f", v)
		f:write(v .. "\n")
	end
	f:close()
end

--! @brief: Counts the number of packets in a PCAP file.
function countPCAPPackets(sourcePCAP, port)
	local pktCounter = 0
	local mem        = memory.createMemPool()
	local buf        = mem:bufArray(1)
	-- Allocate a big enough space because we don't know how big the packets are
	buf:alloc(1500)
	local pcapReader = pcapReader:newPcapReader(sourcePCAP)

	--local f = io.open("trace-"..port..".txt", "w+")

	local see_first_pkt = false

	local pktSize = 0

	while not pcapReader.done do
		local rd   = pcapReader:readPkt(buf, true)
		pktCounter = pktCounter + rd

		if ( not see_first_pkt ) then
			for _, b in ipairs(buf) do
				local data = ffi.cast("uint8_t*", b.pkt.data)
				local pkt = b:getIPPacket()
				pktSize = pkt.ip4:getLength() + ETH_HEADER_LENGHT
				break
			end
			see_first_pkt = true
		end

		--for _, b in ipairs(buf) do
		--	local data = ffi.cast("uint8_t*", b.pkt.data)

		--	-- UDP packet
		--	if ( data[23] == 17 ) then
		--		local pkt = b:getUdpPacket()
		--		--printf("UDP packet %s:%d --> %s:%d", pkt.ip4.src:getString(), pkt.udp:getSrcPort(), pkt.ip4.dst:getString(), pkt.udp:getDstPort())
		--		f:write("Proto ".. pkt.ip4.protocol.."    "..pkt.ip4.src:getString()..":"..pkt.udp:getSrcPort().." --> "..pkt.ip4.dst:getString()..":"..pkt.udp:getDstPort().."\n")

		--		if ( pkt.udp:getSrcPort() == 123 and pkt.udp:getDstPort() == 2401 ) then
		--			printf("======================================================")
		--			printf("FOUND")
		--			printf("======================================================")
		--		end
		--	end
		--	break
		--end
	end

	--f:close()
	buf:freeAll()

	if ( pktSize == 0 ) then
		return log:info([[Packet size detected is zero or negative, something is wrong]])
	end

	return pktCounter, pktSize
end

--! @brief: Load the content of a PCAP file into memory.
function laodPCAPPackets(sourcePCAP, pktSize, pcapSize)
	batchSize = pcapSize
	mem  = memory.createMemPool()
	bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	printf("[PCAP Loader] Allocated space for %d packets", batchSize)
	
	bucketSize = 0
	pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (bucketSize <= batchSize) do
		local rd = pcapReader:readPkt(bufs, true)
		bucketSize = bucketSize + rd
	end
	printf("[PCAP Loader] Loaded %d packets in memory", bufs.size)

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
				--printf("UDP packet %s:%d --> %s:%d", pkt.ip4.src:getString(), pkt.udp.src, pkt.ip4.dst:getString(), pkt.udp.dst)
				udpBuf[#udpBuf+1] = {pkt.ip4.src:getString(), pkt.udp.src, pkt.ip4.dst:getString(), pkt.udp.dst}
				udpCounter = udpCounter + 1

				if ( pkt.udp.src == 123 and pkt.udp.dst == 2401 ) then
					printf("======================================================")
					printf("FOUND")
					printf("======================================================")
				end
			end
			break
		end

		pktCounter = pktCounter + rd
	end
	buf:freeAll()
	--printf("------------------------------------------------------")

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
function pcapSendBucketSlave(txPort, txDev, queueNo, rate, maxPackets, pktSize, sourcePCAP, pcapSize)
	printf("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(queueNo)
	queue:setRate(rate)
	
	local batchSize = 255
	local bufs_no   = 8 --math.ceil(pcapSize / batchSize)
	printf("[Dev %d] PCAP Sender Thread: Prepared %d buckets", txPort, bufs_no)
	local mem  = memory.createMemPool()
	local bufs = {}
	for i=1, bufs_no do
		bufs[i] = mem:bufArray(batchSize)
		bufs[i]:alloc(pktSize)
	end
	printf("[Dev %d] PCAP Sender Thread: Allocated %d bufs each at the size of %d packets", txPort, bufs_no, batchSize)
	
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
	printf("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, pkt)

	local ctr = stats:newDevTxCounter(txDev,"plain")

	local pkt = 1
	while mg.running() and (not maxPackets or pkt <= maxPackets) do
		for i=1, bufs_no do
			queue:send(bufs[i])
			pkt = pkt + bufs[i].size
			ctr:update()
		end
	end

	ctr:finalize()
end
