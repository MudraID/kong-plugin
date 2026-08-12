-- Run the shared conformance corpus against the LUA adapter.
--
-- ``kong/tests/test_adapter_conformance.py`` runs the SAME file against the
-- Python middleware. That is the point: "both adapters enforce the same
-- contract" is only checkable if there is one artefact they are both checked
-- against. Two suites written separately can each be green while disagreeing,
-- because each asserts what its own implementation does — and the
-- disagreement surfaces as a customer whose gateway denies what their
-- middleware allows.
--
-- Run from the repo root:
--     lua kong/tests/lua/test_conformance.lua
--
-- NON-VACUITY IS ASSERTED, the same way the Python runner asserts it: a runner
-- that silently skipped a group would report success having checked nothing.
-- Both print their totals, so a divergence in COVERAGE is as visible as one in
-- behaviour.

package.path = "./?.lua;./kong/plugins/mudraid-enforce/?.lua;" .. package.path

local tests, failures = 0, 0
local function check(cond, name, detail)
  tests = tests + 1
  if cond then
    print("ok   " .. name)
  else
    failures = failures + 1
    print("FAIL " .. name .. (detail and (" — " .. tostring(detail)) or ""))
  end
end

-- ── Minimal JSON reader ─────────────────────────────────────────────────────
--
-- cjson is not available under the plain-LuaJIT harness, and pulling in a
-- dependency to read a test fixture would put a third party between the two
-- adapters and the one file that is supposed to bind them. The corpus is
-- deliberately plain JSON — objects, arrays, strings, numbers, booleans — so a
-- small reader is enough and is itself checkable.
local function decode(text)
  local pos = 1

  local function skip()
    while true do
      local c = text:sub(pos, pos)
      if c == " " or c == "\n" or c == "\t" or c == "\r" then
        pos = pos + 1
      else
        return
      end
    end
  end

  local parse_value

  local function parse_string()
    pos = pos + 1  -- opening quote
    local out = {}
    while true do
      local c = text:sub(pos, pos)
      if c == '"' then
        pos = pos + 1
        return table.concat(out)
      elseif c == "\\" then
        local nxt = text:sub(pos + 1, pos + 1)
        local map = { n = "\n", t = "\t", r = "\r", b = "\b", f = "\f",
                      ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
        out[#out + 1] = map[nxt] or nxt
        pos = pos + 2
      elseif c == "" then
        error("unterminated string in corpus")
      else
        out[#out + 1] = c
        pos = pos + 1
      end
    end
  end

  local function parse_number()
    local s, e = text:find("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
    local n = tonumber(text:sub(s, e))
    pos = e + 1
    return n
  end

  local function parse_array()
    pos = pos + 1
    local out = {}
    skip()
    if text:sub(pos, pos) == "]" then pos = pos + 1 return out end
    while true do
      out[#out + 1] = parse_value()
      skip()
      local c = text:sub(pos, pos)
      pos = pos + 1
      if c == "]" then return out end
      if c ~= "," then error("expected , or ] in corpus at " .. pos) end
      skip()
    end
  end

  local function parse_object()
    pos = pos + 1
    local out = {}
    skip()
    if text:sub(pos, pos) == "}" then pos = pos + 1 return out end
    while true do
      skip()
      local key = parse_string()
      skip()
      pos = pos + 1  -- colon
      out[key] = parse_value()
      skip()
      local c = text:sub(pos, pos)
      pos = pos + 1
      if c == "}" then return out end
      if c ~= "," then error("expected , or } in corpus at " .. pos) end
    end
  end

  parse_value = function()
    skip()
    local c = text:sub(pos, pos)
    if c == "{" then return parse_object() end
    if c == "[" then return parse_array() end
    if c == '"' then return parse_string() end
    if text:sub(pos, pos + 3) == "true" then pos = pos + 4 return true end
    if text:sub(pos, pos + 4) == "false" then pos = pos + 5 return false end
    if text:sub(pos, pos + 3) == "null" then pos = pos + 4 return nil end
    return parse_number()
  end

  return parse_value()
end

local function count(t)
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n
end

-- ── Load the corpus ─────────────────────────────────────────────────────────
-- Resolved from the environment so the SAME runner works from the repository
-- root and inside the image, where the fixtures land somewhere else. Hardcoding
-- one path would mean the image build could not run this gate at all — and a
-- conformance check that only runs on a developer machine is the half that
-- rots.
local corpus_path = os.getenv("MUDRAID_CONFORMANCE_CORPUS")
  or "kong/tests/fixtures/adapter-conformance.json"
local handle = assert(io.open(corpus_path, "r"),
  "corpus not found at " .. corpus_path
  .. "; run from the repository root or set MUDRAID_CONFORMANCE_CORPUS")
local corpus = decode(handle:read("*a"))
handle:close()

-- The reader is itself checked before anything is concluded from what it read.
check(corpus.corpus_version == "1", "corpus loaded and versioned")

-- ── Protected-path boundaries ───────────────────────────────────────────────
local path = require "path"

local path_cases = corpus.protected_path_matching.cases
check(#path_cases >= 10, "the path corpus is not empty",
  "a runner that checked nothing would pass")

for _, case in ipairs(path_cases) do
  local got = path.is_protected(corpus.protected_path_matching.configured, case.path)
  check(got == case.protected,
    string.format("path %-14s -> %s", case.path, tostring(case.protected)),
    case.why)
end

-- ── Reserved headers ────────────────────────────────────────────────────────
local headers = require "headers"

local header_cases = corpus.reserved_headers.cases
check(#header_cases >= 8, "the header corpus is not empty")

-- The two adapters expose this differently and that asymmetry is worth
-- naming rather than hiding: Python's is_reserved_header(name) reads its
-- prefixes from a module constant, while Lua's should_strip(name, prefixes)
-- takes them explicitly because a BUNDLE may widen the strip list at runtime.
--
-- effective_prefixes(nil) is therefore the honest equivalent of the Python
-- default — the built-in floor with no bundle additions. Calling it with a
-- hand-written prefix list instead would test a list this file invented, not
-- the one the adapter actually enforces.
local default_prefixes = headers.effective_prefixes(nil)
check(#default_prefixes >= 1, "the built-in strip floor is not empty")

for _, case in ipairs(header_cases) do
  local got = headers.should_strip(case.header, default_prefixes) and true or false
  check(got == case.reserved,
    string.format("header %-24s -> %s", case.header, tostring(case.reserved)))
end

-- ── Coverage, printed so a divergence in what is CHECKED is visible ─────────
print(string.format(
  "\n  conformance corpus v%s — lua adapter: %d path, %d header = %d cases",
  corpus.corpus_version, #path_cases, #header_cases,
  #path_cases + #header_cases))

-- The decide-response group is NOT run here, and saying so is the point.
-- decide.lua's reader is reached through `decide.call`, which needs an HTTP
-- client; driving it from this corpus would mean building a fake transport in
-- Lua, and a fake shaped by hand is exactly the kind of second implementation
-- this corpus exists to avoid. Those cases run in test_mudraid_enforce.lua
-- against decide.call with an injected client, and in the Python runner
-- against _read_decision directly.
--
-- Stated rather than silently omitted: an unreported gap in coverage is how a
-- conformance claim becomes broader than what was measured.
print("  NOT run here: decide_response_reading ("
  .. #corpus.decide_response_reading.cases
  .. " cases) — see the note at the end of this file")

print(string.format("\n%d tests, %d failures", tests, failures))
if failures > 0 then
  os.exit(1)
end
