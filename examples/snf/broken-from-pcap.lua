--! @file broken-from-pcap.lua
--! @brief Replay from PCAP

local mg	= require "dpdk"
local memory	= require "memory"
local ffi	= require "ffi"
local device	= require "device"
local log	= require "log"
local ts 	= require "timestamping"
local log	= require "log"
local pcap	= require "pcap"
local stats	= require "stats"

ffi.cdef [[
	void* malloc(size_t size);
	void free(void* buf);
	void* alloc_huge(size_t size);
]]

local C = ffi.C
local cast = ffi.cast

function master(txPort, rate, cores, pktSize, maxPackets, sourcePCAP)
	local txPort, rate, cores, pktSize, maxPackets = tonumberall(txPort, rate, cores, pktSize, maxPackets)
	local sourcePCAP = sourcePCAP
	if not txPort or not rate or not cores or not pktSize or not maxPackets or not sourcePCAP then
		return log:info([[
Usage: txPort rate cores pktSize maxPackets sourcePCAP

Reads packets from PCAP and writes them out on txPort.
Transmits at most maxp packets or the entire pcap file if maxp == 0

Example usage:
sudo MoonGen examples/snf/broken-from-pcap.lua 0 10000000000 8 60 0 /home/katsikas/nfv/experimental_traces/wustl_traces/traces/real_acl_8550.pcap
]])
	end

	-- If number of packets to send is not specified (<=0), we loop the PCAP forever
	if (maxPackets <= 0) then maxPackets = nil end
	if ( cores <= 0 ) then cores = 1 end
	-- We divide the total rate among all requested cores
	rate    = (rate / cores) or (10000000000 / cores)

	mg.sleepMillis(100)
	local rxMempool = memory.createMemPool()
	local txDev = device.config({ port=txPort, mempool=rxMempool, rxQueues=1, txQueues=cores })
	txDev:wait()

	print("Source PCAP: ", sourcePCAP)
	print("   Tx  Port: ", txPort)
	print("   Tx Cores: ", cores)
	print("  Rate/Core: ", rate/1000000000,"Gbps")
	print(" Packets No: ", maxPackets)
	print("Packet Size: ", pktSize)

	-- Find the total number of packets of the PCAP file
	local pcapRecords = countPCAPPackets(sourcePCAP, pktSize)
	print("Total PCAP records: ", pcapRecords)
	local pcapRecordsForCore = round(pcapRecords/cores)
	print(" PCAP records/core:", pcapRecordsForCore)
	-- Each core has to transmit a different portion of the file
	local maxPacketsPerCore = 0
	if ( maxPackets == nil ) then
		maxPacketsPerCore = round(pcapRecords/cores)
	else
		maxPacketsPerCore = round(maxPackets/cores)
	end

	-- Start a thread per core
	for i = 0, cores - 1 do
		txDev:getTxQueue(i):setRate(rate)

		local minPCAPRange = i*pcapRecordsForCore + 1
		local maxPCAPRange = minPCAPRange + pcapRecordsForCore - 1
		printf("[Queue %d] MinRange %d, MaxRange %d", i, minPCAPRange, maxPCAPRange)
		mg.launchLua("pcapSendSlave", txPort, i, sourcePCAP, pktSize, minPCAPRange, maxPCAPRange, maxPacketsPerCore, true)
	end
	mg.waitForSlaves()
end

--! @brief: Loads the PCAP file and send batches of packets packet out.
function pcapSendSlave(port, queue, sourcePCAP, pktSize, minPCAPRange, maxPCAPRange, maxPacketsPerCore, showStats)
	printf("[Queue %d] PCAP Sender Thread is running", queue)

	local core      = queue
	local queue     = device.get(port):getTxQueue(queue)

	-- ################ Memory management #################
	local totalPktsNo = maxPCAPRange - minPCAPRange + 1
	local memBankSize = 2047
	local memBanksNo  = round(totalPktsNo / memBankSize)
	local leftOver    = math.abs(totalPktsNo - memBanksNo*memBankSize)
	--printf("[Core %d] Memory Banks: %d, Memory Bank Size: %d packets, PktSize: %d", core, memBanksNo, memBankSize, pktSize)

	local largeBufs   = allocLargeBuf(totalPktsNo, pktSize)
	printf("[Core %d] Huge memory allocated", core)

	local mem   = memory.createMemPool()
	local mBufs = mem:bufArray(memBankSize)
	mBufs:alloc(pktSize)
	printf("[Core %d] %d RTE mbufs allocated, each mbuf is %d bytes", core, memBankSize, pktSize)

	-- Load the PCAP file
	local pcapArg     = 100000
	local pcapReader  = pcapReader:newPcapReader(sourcePCAP, pcapArg)
	local pcapCounter = 0
	local currPktCnt  = 1

	-- Load the appropriate range of packets of the PCAP file into a pre-allocated memory bank (per core).
	loadPCAPFractionInMemory(core, largeBufs, pcapReader, totalPktsNo, minPCAPRange, maxPCAPRange)

	-- Fill the mbufs (DPDK memory pool) with the first chunck of packets from main memory.
	-- Return the updated position of the memory (where to go for the next chunck).
	retVal = fillMBufs(mBufs, largeBufs, maxPacketsPerCore, totalPktsNo, memBankSize, currPktCnt)
	mBufs = retVal[0]
	currPktCnt = retVal[1]
	
	local pkt       = 1
	local curr      = 1
	local lastPrint = mg.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent  = 0
	local ctr = stats:newDevTxCounter(dev, "plain")
	while (mg.running()) and (not maxPacketsPerCore or pkt <= maxPacketsPerCore) do

		if ( pkt >= totalPktsNo ) then pkt=1  end

		-- Send them out and keep statistics
		totalSent = totalSent + queue:sendWithTimestamp(mBufs)
		local time = mg.getTime()
		if time - lastPrint > 1 then
			local mpps = (totalSent - lastTotal) / (time - lastPrint) / 10^6
			printf("[Queue %d] Sent %d packets, current rate %.2f Mpps, %.2f MBit/s, %.2f MBit/s wire rate", core, totalSent, mpps, mpps * pktSize * 8, mpps * (pktSize+20) * 8)
			lastTotal = totalSent
			lastPrint = time
		end

		if showStats then ctr:update() end
	end

	if showStats then ctr:finalize() end

	mg.sleepMillis(500)
	mBufs:freeAll()
	memory.free(largeBufs)

	printf("[Core %d] Sent %d packets", core, totalSent)
end

--! @brief: Counts the number of packets in a PCAP file.
function countPCAPPackets(sourcePCAP, pktSize)
	local pktCounter = 0
	local mem        = memory.createMemPool()
	local buf        = mem:bufArray(1)
	buf:alloc(pktSize)
	local pcapReader = pcapReader:newPcapReader(sourcePCAP)
	while not pcapReader.done do
		pcapReader:readPkt(buf[1], true)
		pktCounter = pktCounter + 1
	end

	buf:freeAll()

	return pktCounter
end

function round(x)
	return x>=0 and math.floor(x+0.5) or math.ceil(x-0.5)
end

function div(a, b)
	q = a/b
	return (q > 0) and math.floor(q) or math.ceil(q)
end

function allocLargeBuf(totalPktsNo, pktSize)
	local largeBufs = {}

	for i = 0, totalPktsNo-1 do
		largeBufs[i] = {}
		--if ( i == memBanksNo-1 ) then
		--	memBankSize = leftOver
		--end
		--largeBufs[i] = mem:bufArray(memBankSize)
		--largeBufs[i]:alloc(pktSize)
		--largeBufs[i] = memory.alloc("struct rte_mbuf*[?]", pktSize)
		largeBufs[i] = ffi.new("struct rte_mbuf*[?]", 1)
		--setmetatable({
		--	size = 1,
		--	maxSize = 1,
		--	array = ffi.new("struct rte_mbuf*[?]", 1),
		--	--mem = self,
		--}, largeBufs[i])
	end

	return largeBufs
end

function loadPCAPFractionInMemory(core, largeBufs, pcapReader, totalPktsNo, minPCAPRange, maxPCAPRange)
	local counter = 0
	local pkt     = 1
	while (not pcapReader.done) and (pkt <= totalPktsNo) do
		if (counter < minPCAPRange) then
			-- Do nothing
		elseif (counter > maxPCAPRange) then
			break
		else
			--local memBank = div(pkt, memBankSize)
			--local pktIndexInMemBank = math.mod(pkt, memBankSize)
			pcapReader:readPkt(largeBufs[pkt], true)
			pkt = pkt + 1
		end
		counter = counter + 1
	end
	printf("[Core %d] Allocated memory for %d packets", core, totalPktsNo)
end

function fillMBufs(mBufs, largeBufs, maxPacketsPerCore, totalPktsNo, memBankSize, currPktCnt)
	local batch = 1
	while (batch <= memBankSize) do
		-- Start replaying the PCAP file
		if ( currPktCnt > totalPktsNo ) then currPktCnt = 1  end

		miniBufs[batch] = largeBufs[currPktCnt]
		currPktCnt = currPktCnt + 1
		batch = batch + 1
	end	

	return mBufs, currPktCnt
end
