function init (args)
	local needs = {}
	needs["payload"] = tostring(true)
	return needs
end

function match(args)
	local b = args['payload']
	if b == nil then
		print ("Payload buffer empty! Aborting...")
		return 0
	end
 
	-- Referenced from McAfee’s Advanced Threat Research team’s code to resolve CVE-2020-16898
	-- https://github.com/advanced-threat-research/CVE-2020-16898/blob/main/cve-2020-16898.lua
	-- The buffer section was used to parse the packets for the desired information.
	local buffer = SCPacketPayload()
	local search_pkt = string.sub(buffer, 1, 8) -- Creates substring of first 8 bytes of buffer
	local s, _ = string.find(b, search_pkt, 1, true) -- This finds a match for the buffer in packet
	local position = s - 4 -- SCPacketPayload() starts at the 5th byte, so we are bringing it back to the beginning of the ICMPv6 header.

	-- Check ICMPv6 packets for Type 134 (Router Advertisement).
	if tonumber(b:byte(position)) == 134 then
		return 1 -- If RA-based DNS configuration is occurring, trigger the rule.
	else
		return 0
	end
end