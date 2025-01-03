local json = require("dkjson")

local welcome_message = [[
 █████████████████████████████████████████████████████████████████████                    
  |                         TailTrace                               |
  |                         /\_____/\                               |
  |                        /  o   o  \  < Meow! Network sniffed!    |
  |                       ( ==  ^  == )                             |
  |                        )         (                              |
  |                       (           )                             |
  |                      ( (  )   (  ) )                            |
  |                     (__(__)___(__)__)                           |
  |                                                                 |
  █████████████████████████████████████████████████████████████████████
  --=[ TailTrace v1.0.0 ]=--
]]

print(welcome_message)

local tailtrace_proto = Proto("tailtrace", "TailTrace Protocol Analyzer")

tailtrace_proto.fields.source = ProtoField.string("tailtrace.source", "Source")
tailtrace_proto.fields.destination = ProtoField.string("tailtrace.destination", "Destination")
tailtrace_proto.fields.protocol = ProtoField.string("tailtrace.protocol", "Protocol")
tailtrace_proto.fields.length = ProtoField.uint32("tailtrace.length", "Packet Length")
tailtrace_proto.fields.info = ProtoField.string("tailtrace.info", "Info")
tailtrace_proto.fields.ml_result = ProtoField.string("tailtrace.ml_result", "ML Analysis")
tailtrace_proto.fields.ids_alert = ProtoField.string("tailtrace.ids_alert", "IDS Alert")

local function signature_analysis(info)
    local signatures = {
        { pattern = "malicious", alert = "Malware detected" },
        { pattern = "scan", alert = "Port scan detected" },
        { pattern = "ddos", alert = "DDoS activity detected" }
    }
    for _, sig in ipairs(signatures) do
        if string.match(info, sig.pattern) then
            return sig.alert
        end
    end
    return "No signature match"
end

function call_python_ml(packet_data)
    local temp_file = "packet_data.json"
    local file = io.open(temp_file, "w")
    file:write(json.encode(packet_data))
    file:close()

    local cmd = "python3 ml_analysis.py " .. temp_file
    local result = io.popen(cmd):read("*all")
    os.remove(temp_file)
    return result
end

function call_python_ids(packet_data)
    local temp_file = "packet_data.json"
    local file = io.open(temp_file, "w")
    file:write(json.encode(packet_data))
    file:close()

    local cmd = "python3 ids_analysis.py " .. temp_file
    local result = io.popen(cmd):read("*all")
    os.remove(temp_file)
    return result
end

tailtrace_proto.dissector = function(buffer, pinfo, tree)
    local subtree = tree:add(tailtrace_proto, buffer(), "TailTrace Analysis")
    local src = tostring(pinfo.src)
    local dst = tostring(pinfo.dst)
    local proto = tostring(pinfo.protocol)
    local length = buffer:len()
    local info = tostring(pinfo.cols.info)

    subtree:add(tailtrace_proto.fields.source, src)
    subtree:add(tailtrace_proto.fields.destination, dst)
    subtree:add(tailtrace_proto.fields.protocol, proto)
    subtree:add(tailtrace_proto.fields.length, length)
    subtree:add(tailtrace_proto.fields.info, info)

    local sig_alert = signature_analysis(info)
    subtree:add(tailtrace_proto.fields.ids_alert, sig_alert)

    local ml_result = call_python_ml({ src = src, dst = dst, proto = proto, length = length, info = info })
    subtree:add(tailtrace_proto.fields.ml_result, ml_result)

    local ids_result = call_python_ids({ src = src, dst = dst, proto = proto, length = length, info = info })
    subtree:add(tailtrace_proto.fields.ids_alert, ids_result)

    pinfo.cols.info:set(pinfo.cols.info .. " [TailTrace Analysis]")
end

DissectorTable.get("tcp.port"):add(12345, tailtrace_proto)
