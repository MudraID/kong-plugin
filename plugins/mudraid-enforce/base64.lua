-- mudraid-enforce: strict base64 decoding.
--
-- Its own module, and pure Lua, for the same reason canonical.lua and
-- compare.lua are: `crypto.lua` requires the resty/OpenSSL bindings at module
-- load, so it cannot be required by the plain-LuaJIT unit harness at all. Any
-- logic that needs testing outside the gateway image has to live outside it.
--
-- Decoding a signature is exactly such a piece of logic, and it is one worth
-- testing: this refuses malformed input rather than silently repairing it.

local _M = {}

-- `ngx.decode_base64` is unavailable under the plain-LuaJIT harness the plugin
-- tests run in, and it is also LENIENT — it accepts input with invalid
-- characters by skipping them. That leniency is wrong here: a signature is an
-- authentication tag, and silently discarding bytes from one changes what is
-- being verified. This refuses anything that is not well-formed base64.
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_INDEX = {}
for i = 1, #B64 do B64_INDEX[B64:sub(i, i)] = i - 1 end

function _M.decode(s)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  if #s % 4 ~= 0 then
    return nil
  end
  local body, pad = s, 0
  local tail = s:sub(-2)
  if tail == "==" then
    body, pad = s:sub(1, -3), 2
  elseif s:sub(-1) == "=" then
    body, pad = s:sub(1, -2), 1
  end

  local bits, nbits, out = 0, 0, {}
  for i = 1, #body do
    local v = B64_INDEX[body:sub(i, i)]
    if v == nil then
      return nil  -- refuse rather than skip
    end
    bits = bits * 64 + v
    nbits = nbits + 6
    if nbits >= 8 then
      nbits = nbits - 8
      local byte = math.floor(bits / (2 ^ nbits))
      bits = bits - byte * (2 ^ nbits)
      out[#out + 1] = string.char(byte)
    end
  end
  -- Any leftover bits must be zero; non-zero padding bits mean malformed input.
  if pad > 0 and bits ~= 0 then
    return nil
  end
  return table.concat(out)
end


return _M
