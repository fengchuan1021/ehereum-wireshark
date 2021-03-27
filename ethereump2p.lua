local s2=require('sha2')
ethereump2p = Proto("ethereump2p", "ethereump2p_nodefinde")
-- Header fields
msg_hash = ProtoField.bytes ("ethereump2p.msg_hash", "msg_hash", base.NONE)
signature     = ProtoField.bytes("ethereump2p.signature"    , "signature"    , base.NONE)

ethereump2p.fields = { msg_hash, signature }

local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    length = buffer:len()
    if length < 98 then return false end
	
    return ethereump2p.dissector(buffer, pinfo, tree)

end

local function get_message_name(msg_id)
    local message_name = "Unknown"

        if msg_id == 0x0001 then message_name = "_PING"
    elseif msg_id == 2 then message_name = "_PONG"
    elseif msg_id == 3 then message_name = "_FIND_NODE"
    elseif msg_id == 4 then message_name = "_NEIGHBOURS"
    elseif msg_id == 5 then message_name = "_ENR_REQUEST"
    elseif msg_id == 6 then message_name = "_ENR_RESPONSE" end

    return message_name
end

function ethereump2p.dissector(buffer, pinfo, tree)
    local length = buffer:len()
	local msg_hash_str=buffer(0,32)
	local row_str=buffer():raw()
	local data_str=string.sub(row_str,33)
	if string.upper(s2.sha3_256(data_str)) ~= tostring(msg_hash_str:bytes()) then
		return false
	end
	
    local read_msg_id = buffer(97,1):uint()
    local message_name = get_message_name(read_msg_id)
    --subtree:add(msg_id, buffer(1,2)):append_text(" (" .. message_name .. ")")
    pinfo.cols.protocol = ethereump2p.name..message_name

    local subtree = tree:add(ethereump2p, buffer(), "Ethereum nodefind p2p proto")

    -- Header
    subtree:add(msg_hash,msg_hash_str)
	subtree:add(signature, buffer(32,65))
    --local read_msg_id = buffer(1,2):uint()
    --local message_name = get_message_name(read_msg_id)
    --subtree:add(msg_id, buffer(1,2)):append_text(" (" .. message_name .. ")")
end

ethereump2p:register_heuristic("udp", heuristic_checker)