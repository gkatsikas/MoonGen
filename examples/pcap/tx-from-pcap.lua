--! @file tx-from-pcap.lua
--! @brief Replay from Pcap with correct delays

local mg	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local log	= require "log"
local ts 	= require "timestamping"
local pcap	= require "pcap"
local stats	= require "stats"
local hist	= require "histogram"

local MAX_PCAP_PKTS_NO = 2048

-- sudo MoonGen examples/pcap/tx-from-pcap.lua 0 1 10000000000 64 0 /home/katsikas/nfv/hypernf-controller/data/original/acl_251_compressed.pcap

function master(txPort, rxPort, rate, pktSize, maxPackets, sourcePCAP)
	local txPort, rxPort, rate, pktSize, maxPackets = tonumberall(txPort, rxPort, rate, pktSize, maxPackets)
	if not txPort or not rxPort or not rate or not maxPackets or not pktSize or not sourcePCAP then
		return log:info([[Usage: txPort rxPort rate pktSize maxPackets sourcePCAP]])
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
	mg.sleepMillis(100)

	-- Find how many packets there are in the input pcap file
	local pcapSize = countPCAPPackets(sourcePCAP, 128)
	printf("Input PCAP file contains %d packets", pcapSize)

	if pcapSize > MAX_PCAP_PKTS_NO then
		return log:info([[PCAP file contains more than %d packets]], MAX_PCAP_PKTS_NO)
	end

	mg.launchLua("pcapSendSlave",  txPort, txDev, rate, pktSize, maxPackets, pcapSize, sourcePCAP)
	mg.launchLua("rxCounterSlave", rxPort, rxDev)
	hwTimestamper(txPort, rxPort, txDev:getTxQueue(1), rxDev:getRxQueue(1))
	mg.waitForSlaves()
end

--! @brief: sends a packet out
function pcapSendSlave(txPort, txDev, rate, pktSize, maxPackets, pcapSize, sourcePCAP)
	printf("[Dev %d] Tx PCAP Thread is running", txPort)
	-- Prepare sender queue and set the rate
	local queue = txDev:getTxQueue(0)
	queue:setRate(rate)

	local batchSize = pcapSize
	local mem  = memory.createMemPool()
	local bufs = mem:bufArray(batchSize)
	bufs:alloc(pktSize)
	printf("[Dev %d] PCAP Sender Thread: Allocated space for %d packets", txPort, batchSize)
	
	local bucketSize = 0
	local pcapReader = pcapReader:newPcapReader(sourcePCAP, 10000)
	while not pcapReader.done and (not maxPackets or pkt <= maxPackets) and (bucketSize <= batchSize) do
		local rd = pcapReader:readPkt(bufs, true)
		bucketSize = bucketSize + rd
	end
	printf("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, bufs.size)

	local pkt = 1
	local ctr = stats:newDevTxCounter(txDev,"plain")
	while mg.running() and (not maxPackets or pkt <= maxPackets) do
		queue:send(bufs)
		pkt = pkt + bufs.size
		ctr:update()
	end

	ctr:finalize()
end

--! @brief: sends a packet out
function pcapSendBucketSlave(txPort, txDev, rate, pktSize, maxPackets, pcapSize, sourcePCAP)
	printf("[Dev %d] Tx PCAP Thread is running", txPort)
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
	printf("[Dev %d] PCAP Sender Thread: Allocated %d bufs each at the size of %d packets", txPort, bufs_no, batchSize)
	
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
	printf("[Dev %d] PCAP Sender Thread: Loaded %d packets in memory", txPort, pkt)

	local ctr = stats:newDevTxCounter(txDev,"plain")

	local pkt = 1
	while mg.running() and (not maxPackets or pkt <= maxPackets) do
		for i = 0, bufs_no-1 do
			queue:send(bufs[i])
			pkt = pkt + bufs[i].size
			ctr:update()
		end
	end

	ctr:finalize()
end

function rxCounterSlave(rxDevNo, rxDev)
	local queue = rxDev:getRxQueue(0)
	printf("[Dev %d] Rx Slave", rxDevNo)
	local bufs = memory.bufArray()
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	local pkts = 0
	while mg.running() do
		local rx = queue:recv(bufs)
		pkts = pkts + rx
		ctr:update()
		bufs:freeAll()
	end
	ctr:finalize()
	printf("[Dev %d] Rx terminated after receiving %d packets", rxDevNo, pkts)
end

function hwTimestamper(txPort, rxPort, txQueue, rxQueue)
	printf("[HW Timestamper - Tx Port %d, Rx Port %d]", txPort, rxPort)
	local timestamper = ts:newTimestamper(txQueue, rxQueue)
	local hist = hist:new()
	while mg.running() do
		hist:update(timestamper:measureLatency())
	end
	--hist:save("histogram.csv")
	--hist:print()
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
