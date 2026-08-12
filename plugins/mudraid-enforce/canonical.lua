-- mudraid-enforce: canonical JSON serialization (EP-110-US-04, doc 03 A03-05).
--
-- MUST produce byte-identical output to the control plane's signer:
--   services/platform-integration-service/app/application/bundle_compiler.py
--     canonical_json_bytes(value) ==
--       json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
--
-- Python's json.dumps defaults imply ensure_ascii=True, so:
--   * object keys sorted (byte order == code-point order for UTF-8);
--   * no whitespace;
--   * every non-ASCII character escaped as \uXXXX (lowercase hex,
--     UTF-16 surrogate pairs above the BMP);
--   * control characters use the short escapes \b \t \n \f \r where they
--     exist, \u00XX otherwise; only `"` and `\` are otherwise escaped.
--
-- The encoder is deliberately REFUSING rather than lenient: any value it
-- cannot canonicalize with certainty (non-integer numbers, non-string keys,
-- mixed array/hash tables, unknown types) returns an error, and the caller
-- (bundle verification) treats that as an invalid bundle. A digest computed
-- over a "best effort" serialization would silently accept tampering.
--
-- Pure Lua 5.1+ — no ngx/Kong dependencies — so the module is unit-testable
-- outside the gateway (kong/tests/lua/).

local _M = {}

local SHORT_ESCAPES = {
  [8] = "\\b",
  [9] = "\\t",
  [10] = "\\n",
  [12] = "\\f",
  [13] = "\\r",
  [34] = '\\"',
  [92] = "\\\\",
}

-- Decode one UTF-8 sequence starting at byte position i.
-- Returns codepoint, next_index or nil, error.
local function utf8_decode(s, i)
  local b1 = s:byte(i)
  if b1 < 0x80 then
    return b1, i + 1
  end
  local len, cp
  if b1 >= 0xC2 and b1 <= 0xDF then
    len, cp = 2, b1 - 0xC0
  elseif b1 >= 0xE0 and b1 <= 0xEF then
    len, cp = 3, b1 - 0xE0
  elseif b1 >= 0xF0 and b1 <= 0xF4 then
    len, cp = 4, b1 - 0xF0
  else
    return nil, "invalid UTF-8 lead byte"
  end
  for k = 1, len - 1 do
    local b = s:byte(i + k)
    if not b or b < 0x80 or b > 0xBF then
      return nil, "truncated/invalid UTF-8 continuation"
    end
    cp = cp * 64 + (b - 0x80)
  end
  -- Reject overlong encodings and surrogates: the signer never emits them.
  if (len == 2 and cp < 0x80)
    or (len == 3 and cp < 0x800)
    or (len == 4 and cp < 0x10000)
    or (cp >= 0xD800 and cp <= 0xDFFF)
    or cp > 0x10FFFF
  then
    return nil, "invalid UTF-8 codepoint"
  end
  return cp, i + len
end

local function encode_string(s, out)
  out[#out + 1] = '"'
  local i, n = 1, #s
  while i <= n do
    local b = s:byte(i)
    if b < 0x80 then
      local esc = SHORT_ESCAPES[b]
      if esc then
        out[#out + 1] = esc
      elseif b < 0x20 then
        out[#out + 1] = string.format("\\u%04x", b)
      else
        out[#out + 1] = s:sub(i, i)
      end
      i = i + 1
    else
      local cp, nxt = utf8_decode(s, i)
      if not cp then
        return nil, nxt
      end
      if cp < 0x10000 then
        out[#out + 1] = string.format("\\u%04x", cp)
      else
        local v = cp - 0x10000
        out[#out + 1] = string.format(
          "\\u%04x\\u%04x",
          0xD800 + math.floor(v / 0x400),
          0xDC00 + (v % 0x400)
        )
      end
      i = nxt
    end
  end
  out[#out + 1] = '"'
  return true
end

local function encode_number(v)
  -- The bundle contract carries only integers (versions, revisions, counts).
  -- Non-integer floats have no guaranteed cross-language canonical form
  -- (Python repr vs Lua %g), so they are REFUSED rather than approximated.
  if v ~= v or v == math.huge or v == -math.huge then
    return nil, "non-finite number"
  end
  if math.floor(v) ~= v or v > 2 ^ 53 or v < -(2 ^ 53) then
    return nil, "non-integer number has no canonical form"
  end
  return string.format("%.0f", v)
end

-- Decide array-ness. opts.array_mt (e.g. cjson.array_mt) marks decoded JSON
-- arrays even when empty; otherwise a table with a contiguous 1..n integer
-- sequence and no other keys is an array. An empty table WITHOUT the array
-- metatable is an object ({}), matching cjson's decode default.
local function classify_table(t, opts)
  if opts and opts.array_mt and getmetatable(t) == opts.array_mt then
    return "array"
  end
  local count = 0
  for k in pairs(t) do
    count = count + 1
    if type(k) ~= "number" then
      if type(k) ~= "string" then
        return nil, "non-string object key"
      end
      -- string key present -> object; but mixed with array part is refused
      -- below by the length check.
    end
  end
  local seq = #t
  if seq == 0 then
    -- pure hash (or empty) -> object; verify no numeric keys leaked in
    for k in pairs(t) do
      if type(k) == "number" then
        return nil, "sparse/mixed table cannot be canonicalized"
      end
    end
    return "object"
  end
  if seq == count then
    return "array"
  end
  return nil, "mixed array/hash table cannot be canonicalized"
end

local function encode_value(v, out, opts)
  if opts and opts.null ~= nil and v == opts.null then
    out[#out + 1] = "null"
    return true
  end
  local t = type(v)
  if t == "string" then
    return encode_string(v, out)
  elseif t == "number" then
    local enc, err = encode_number(v)
    if not enc then
      return nil, err
    end
    out[#out + 1] = enc
    return true
  elseif t == "boolean" then
    out[#out + 1] = v and "true" or "false"
    return true
  elseif t == "table" then
    local kind, kerr = classify_table(v, opts)
    if not kind then
      return nil, kerr
    end
    if kind == "array" then
      out[#out + 1] = "["
      for i = 1, #v do
        if i > 1 then
          out[#out + 1] = ","
        end
        local ok, err = encode_value(v[i], out, opts)
        if not ok then
          return nil, err
        end
      end
      out[#out + 1] = "]"
      return true
    end
    -- object: keys sorted bytewise == Python's sort_keys code-point order
    local keys = {}
    for k in pairs(v) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    out[#out + 1] = "{"
    for i = 1, #keys do
      if i > 1 then
        out[#out + 1] = ","
      end
      local ok, err = encode_string(keys[i], out)
      if not ok then
        return nil, err
      end
      out[#out + 1] = ":"
      ok, err = encode_value(v[keys[i]], out, opts)
      if not ok then
        return nil, err
      end
    end
    out[#out + 1] = "}"
    return true
  end
  return nil, "unsupported value type: " .. t
end

--- Canonically encode a decoded-JSON value.
-- @param v     the value (table/string/number/boolean/opts.null)
-- @param opts  { null = <null sentinel, e.g. cjson.null>,
--                array_mt = <array metatable, e.g. cjson.array_mt> }
-- @return canonical string, or nil + error
function _M.encode(v, opts)
  local out = {}
  local ok, err = encode_value(v, out, opts)
  if not ok then
    return nil, err
  end
  return table.concat(out)
end

return _M
