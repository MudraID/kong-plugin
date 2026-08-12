-- mudraid-enforce: reserved-header policy (EP-110-US-04, doc 03 A03-04).
--
-- No authority comes from public headers: every client-supplied reserved
-- header is stripped BEFORE any evaluation on a bundled surface. The strip
-- list is server-owned bundle configuration
-- (payload.content.trusted_context.strip_request_header_prefixes); the
-- DEFAULT below is the defense-in-depth floor applied even when no valid
-- bundle exists yet (a request that will be denied 503 must still never
-- carry spoofed x-mudraid-* headers if an error path ever forwards it).
--
-- Pure Lua — unit-testable outside the gateway.

local _M = {}

-- Mirrors RESERVED_HEADER_PREFIXES in
-- services/platform-integration-service/app/application/bundle_compiler.py
_M.DEFAULT_STRIP_PREFIXES = { "x-mudraid-" }

--- Should this request header be stripped before evaluation?
-- Header names are case-insensitive (RFC 9110); prefixes are matched on the
-- lowercased name.
-- @param name      header name as received
-- @param prefixes  array of lowercase prefixes (defaults applied by caller)
function _M.should_strip(name, prefixes)
  if type(name) ~= "string" or name == "" then
    return false
  end
  local lower = name:lower()
  for i = 1, #prefixes do
    local p = prefixes[i]
    if lower:sub(1, #p) == p then
      return true
    end
  end
  return false
end

--- Normalize the bundle-supplied strip list: lowercase, drop non-strings,
-- and always include the built-in defaults (the bundle can only widen the
-- strip list, never narrow it below the A03-04 floor).
function _M.effective_prefixes(bundle_prefixes)
  local out, seen = {}, {}
  local function add(p)
    if type(p) == "string" and p ~= "" then
      local lower = p:lower()
      if not seen[lower] then
        seen[lower] = true
        out[#out + 1] = lower
      end
    end
  end
  for i = 1, #_M.DEFAULT_STRIP_PREFIXES do
    add(_M.DEFAULT_STRIP_PREFIXES[i])
  end
  if type(bundle_prefixes) == "table" then
    for i = 1, #bundle_prefixes do
      add(bundle_prefixes[i])
    end
  end
  return out
end

return _M
