-- The two adapters must derive the SAME endpoints from the same base URL.
--
-- This suite reads the PYTHON client's path constants out of its source and
-- compares them to this plugin's. Not a copy of them — a copy is what let the
-- two adapters diverge in the first place, and a test asserting a literal it
-- also declares proves only that the file is self-consistent.
--
-- Run from the repo root:
--     lua kong/tests/lua/test_endpoints.lua

package.path = "./?.lua;./kong/plugins/mudraid-enforce/?.lua;" .. package.path

local tests, failures = 0, 0
local function check(cond, name, detail)
  tests = tests + 1
  if cond then
    print("ok   " .. name)
  else
    failures = failures + 1
    print("FAIL " .. name .. (detail and ("  — " .. tostring(detail)) or ""))
  end
end

local endpoints = require "kong.plugins.mudraid-enforce.endpoints"

-- ── The Python client's constants, read from its source ─────────────────────
local PY = os.getenv("MUDRAID_DECIDE_CLIENT_PY")
  or "sdks/mudraid-middleware-python/src/mudraid_platform_middleware/decide_client.py"

local handle = assert(io.open(PY, "r"),
  "decide_client.py not found at " .. PY
  .. "; run from the repository root or set MUDRAID_DECIDE_CLIENT_PY")
local source = handle:read("*a")
handle:close()

local function python_path(name)
  return source:match(name .. '%s*=%s*"([^"]+)"')
end

local py_bundle = python_path("_BUNDLE_PATH")
local py_decide = python_path("_DECIDE_PATH")
local py_keys = python_path("_KEYS_PATH")

-- Non-vacuity first: if the constants could not be READ, every comparison
-- below would compare nil to nil and pass while measuring nothing.
check(py_bundle ~= nil, "read _BUNDLE_PATH from the python client")
check(py_decide ~= nil, "read _DECIDE_PATH from the python client")
check(py_keys ~= nil, "read _KEYS_PATH from the python client")

check(endpoints.BUNDLE_PATH == py_bundle,
  "bundle path agrees with the python middleware",
  tostring(endpoints.BUNDLE_PATH) .. " vs " .. tostring(py_bundle))
check(endpoints.DECIDE_PATH == py_decide,
  "decide path agrees with the python middleware",
  tostring(endpoints.DECIDE_PATH) .. " vs " .. tostring(py_decide))
check(endpoints.KEYS_PATH == py_keys,
  "keys path agrees with the python middleware",
  tostring(endpoints.KEYS_PATH) .. " vs " .. tostring(py_keys))

-- ── The public channel, not the internal one ────────────────────────────────
-- The defect this whole change exists to remove: a customer-installed adapter
-- calling `/api/v1/internal/*`, which is not routed for them and is not theirs
-- to call.
for _, path in ipairs({
  endpoints.BUNDLE_PATH, endpoints.DECIDE_PATH, endpoints.KEYS_PATH,
  endpoints.HEARTBEAT_PATH, endpoints.ACK_PATH,
}) do
  check(path:match("^/api/v1/adapter/enforcement/") ~= nil,
    "public channel: " .. path)
  check(path:match("internal") == nil,
    "no internal path leaks into the customer channel: " .. path)
end

-- ── Base-URL normalisation ──────────────────────────────────────────────────
check(endpoints.normalize_base("https://api.example.test/") == "https://api.example.test",
  "a trailing slash derives the same URL as none")
check(endpoints.normalize_base("https://api.example.test///") == "https://api.example.test",
  "repeated trailing slashes collapse")
check(endpoints.normalize_base("  https://api.example.test  ") == "https://api.example.test",
  "surrounding whitespace is stripped")

-- Refusals. Each returns nil rather than something concatenable: a partial
-- base would produce a request to a relative path, which is how a
-- misconfiguration becomes a request somewhere unintended.
for _, bad in ipairs({ "", "   ", "api.example.test", "ftp://api.example.test", "/api/v1" }) do
  check(endpoints.normalize_base(bad) == nil,
    "refuses a base that is not an http(s) origin: '" .. bad .. "'")
end
check(endpoints.normalize_base(nil) == nil, "refuses a nil base")
check(endpoints.normalize_base(42) == nil, "refuses a non-string base")

-- ── Derivation and overrides ────────────────────────────────────────────────
local conf = { base_url = "https://api.example.test", adapter_token = "tok" }
check(endpoints.decide_url(conf) == "https://api.example.test/api/v1/adapter/enforcement/decide",
  "decide URL derives from base_url alone")
check(endpoints.bundle_url(conf) == "https://api.example.test/api/v1/adapter/enforcement/bundle",
  "bundle URL derives from base_url alone")
check(endpoints.keys_url(conf) == "https://api.example.test/api/v1/adapter/enforcement/keys",
  "keys URL derives from base_url alone")

local overridden = {
  base_url = "https://api.example.test",
  decide_url = "http://127.0.0.1:9999/stub",
  adapter_token = "tok",
}
check(endpoints.decide_url(overridden) == "http://127.0.0.1:9999/stub",
  "an explicit decide_url override replaces exactly one derived URL")
check(endpoints.bundle_url(overridden) == "https://api.example.test/api/v1/adapter/enforcement/bundle",
  "...and leaves the others derived")

-- No base and no override is a REFUSAL, not a relative path.
local empty = {}
check(endpoints.decide_url(empty) == nil, "no base and no override refuses")
local _, why = endpoints.decide_url(empty)
check(type(why) == "string" and why ~= "", "the refusal says why")

-- ── The bearer ──────────────────────────────────────────────────────────────
check(endpoints.bearer({ adapter_token = "abc" }) == "Bearer abc",
  "the adapter token is presented as a bearer")
check(endpoints.bearer({}) == nil, "no token means no call, never an anonymous one")
check(endpoints.bearer({ adapter_token = "" }) == nil, "an empty token is not a token")
-- Specifically NOT falling back to any other configured secret.
check(endpoints.bearer({ decide_service_secret = "internal-secret" }) == nil,
  "the internal service secret is never used as an adapter bearer")

-- ── No customer-facing module may reach for an internal path or secret ──────
--
-- The property P0-2 is about, asserted across the WHOLE plugin rather than the
-- two files that were fixed. A future module added by someone who copied an
-- older one is exactly how this comes back, and it would not be caught by
-- testing endpoints.lua alone.
--
-- containment.lua is exempt and the exemption is named rather than silent: the
-- signed containment feed is a SEPARATE channel owned by enforcement-service,
-- authenticated by its own per-(org, environment, adapter) credential, and is
-- not part of the customer adapter channel. Its transport is a different
-- subject with a different credential, tracked separately.
local CUSTOMER_MODULES = {
  "decide.lua", "channel.lua", "bundle.lua", "ack.lua", "handler.lua",
}

for _, name in ipairs(CUSTOMER_MODULES) do
  local fh = io.open("kong/plugins/mudraid-enforce/" .. name, "r")
  check(fh ~= nil, "readable: " .. name)
  if fh then
    local src = fh:read("*a")
    fh:close()
    -- Comments are stripped first: this file's own prose explains the change
    -- and names the old paths, and a guard that fired on its own explanation
    -- would be one nobody could write honestly.
    local code = src:gsub("%-%-[^\n]*", "")
    check(code:match("/api/v1/internal/enforcement") == nil,
      name .. " does not call an internal enforcement path")
    if name == "channel.lua" then
      -- channel.lua HOUSES TWO CHANNELS, and a file-level check cannot tell
      -- them apart. The adapter channel (heartbeat/bundle/acks) is the
      -- customer's and carries only the per-adapter bearer. The signed
      -- CONTAINMENT feed is enforcement-service's, authenticated by its own
      -- per-(org, environment, adapter) credential over X-Service-Secret, and
      -- is not part of the customer adapter channel.
      --
      -- So the assertion is positional rather than absent: every occurrence
      -- must fall AFTER the containment section begins. Exempting the file
      -- outright would have let the adapter channel regain the secret silently.
      --
      -- That the two live in one file is itself worth fixing — a separate
      -- transport module would make this checkable by name instead of by
      -- offset — and it is recorded rather than done here.
      -- Anchored on the containment transport FUNCTION, not on a comment:
      -- comments are stripped above, so a comment marker is unfindable here,
      -- and anchoring on prose would let a renamed section silently disable
      -- the check.
      local marker = code:find("local function service_request")
      check(marker ~= nil, "channel.lua declares the containment transport")
      local first = code:find("X%-Service%-Secret")
      check(first == nil or (marker ~= nil and first > marker),
        "channel.lua uses the service secret ONLY for the containment feed")
    else
      check(code:match("X%-Service%-Secret") == nil,
        name .. " does not present MudraID's shared workload secret")
    end
    check(code:match("decide_service_secret") == nil,
      name .. " does not read the internal service secret from config")
  end
end

print(string.format("\n%d tests, %d failures", tests, failures))
if failures > 0 then
  os.exit(1)
end
