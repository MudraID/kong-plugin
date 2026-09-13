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
-- Pinned, not merely read: corpus_version moves when a case stops being
-- readable by a runner that does not know a new field. v3 added
-- require_signed_decisions, and a v2 runner would read the mandatory-mode
-- case as if the mode were off and report it green having asserted the
-- opposite contract.
check(corpus.corpus_version == "3", "corpus loaded and versioned")

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

-- ── /decide response SIGNATURE verification (AUDIT-009 A9-02) ───────────────
--
-- The vectors are minted by the REAL authority signer
-- (enforcement-service's decision_signature.py); this runner is the Lua half
-- of the two-adapter conformance claim (Python:
-- kong/tests/test_adapter_conformance.py).
--
-- The group runs against TWO entry points, because it makes two different
-- claims. SIGNED cases go to decide.verify_signature — the pure verifier the
-- hot path calls — with REAL RS256 via crypto.lua, so they run only where the
-- OpenSSL bindings exist: inside the gateway image build (kong/Dockerfile),
-- which is the host the plugin actually executes in; under a plain-LuaJIT
-- harness they are SKIPPED LOUDLY below. UNSIGNED cases make a claim about
-- what an ABSENT signature MEANS, which is the operator's
-- `require_signed_decisions` setting and involves no crypto at all, so they
-- go to decide.read_response and run EVERYWHERE.
--
-- Either way the skip is reported: an unreported gap in coverage is how a
-- conformance claim becomes broader than what was measured.
local signature_cases_run = 0
local unsigned_cases_run = 0
local sig_group = corpus.decide_response_signature
local ok_decide, decide = pcall(require, "decide")
local ok_cjson, cjson = pcall(require, "cjson.safe")
local ok_crypto, crypto = pcall(require, "crypto")
local rsa_available = ok_crypto and (function()
  local ok_pkey = pcall(require, "resty.openssl.pkey")
  return ok_pkey
end)()

-- ── UNSIGNED responses: what ABSENCE means, in both requirement modes ───────
--
-- These are the cases the corpus marks signature_valid null, and they used to
-- be skipped here outright. What that skip was legitimately for: the loop
-- below drives decide.verify_signature, the PURE signature verifier, and a
-- response with no signature gives it nothing to verify — feeding it one
-- would assert something meaningless. So the skip was ROUTING, not exclusion,
-- and it was only ever correct because there was a single null case whose
-- contract (an unsigned response is read) the Python runner did assert.
--
-- That stopped being true when `require_signed_decisions` arrived, because an
-- unsigned response now means opposite things in the two modes, and a
-- contract asserted on one adapter only is exactly what this file exists to
-- refuse. So the null cases are ROUTED rather than dropped: to
-- decide.read_response, the pure reader where ABSENCE is governed
-- (schema.lua's require_signed_decisions reaches it as
-- verify_opts.require_signed, via handler.lua).
--
-- Deliberately OUTSIDE the RS256 guard below. Absence handling needs no
-- crypto at all, so gating it on resty.openssl would leave the mandatory-mode
-- case unrun everywhere except the image build — a corpus case that never
-- executes reads as coverage while providing none.
if sig_group and ok_decide and ok_cjson then
  -- read_response's second return is the REFUSAL detail on "error" and the
  -- whole decoded response on allow/deny — where `reason` is the authority's
  -- reason OBJECT, not a code. Printing it blind would report "table: 0x..."
  -- as the reason a case failed, which is worse than saying nothing.
  local function reason_of(detail)
    if type(detail) ~= "table" then return "no detail" end
    if type(detail.reason) ~= "string" then return "no reason code" end
    return detail.reason
  end

  local unsigned = {}
  for _, case in ipairs(sig_group.cases) do
    if case.signature_valid == nil then unsigned[#unsigned + 1] = case end
  end
  -- Both modes, or the pair proves nothing: a single case in either mode
  -- passes on an adapter that ignores the setting entirely.
  local off_seen, on_seen = false, false
  for _, case in ipairs(unsigned) do
    if case.require_signed_decisions then on_seen = true else off_seen = true end
  end
  check(off_seen and on_seen,
    "both require_signed_decisions modes are covered for an unsigned response",
    "one mode alone passes on an adapter that ignores the setting")

  for _, case in ipairs(unsigned) do
    -- read_response takes the raw body, so the corpus object is re-encoded.
    -- Every field it reads — schema_version, decision_id, decided_at,
    -- deadline_at, signature, decision — survives that round trip unchanged;
    -- what does not (JSON null inside `reason`, an empty array becoming an
    -- empty object) is never read by the reader.
    -- cjson.safe returns nil+err rather than raising, and a nil body would
    -- reach read_response as a length error blamed on the adapter.
    local body = assert(cjson.encode(case.response),
      "could not re-encode corpus case: " .. case.name)
    local status, detail = decide.read_response(
      body,
      sig_group.expected_decision_id,
      {
        -- Mirrors handler.lua's verify_opts, including json.null so a
        -- `"signature": null` is recognised as ABSENCE rather than as a
        -- malformed signature object.
        crypto = ok_crypto and crypto or nil,
        json = { null = cjson.null },
        keys = sig_group.keys,
        require_signed = case.require_signed_decisions and true or false,
        expected = {
          platform_id = sig_group.expected.platform_id,
          environment = sig_group.expected.environment,
          canonical_resource_uri = sig_group.expected.canonical_resource_uri,
          action_key = sig_group.expected.action_key,
          bundle_version = sig_group.expected.bundle_version,
        },
        now = sig_group.verification_now_epoch,
      })
    check(status == case.outcome, "unsigned: " .. case.name,
      string.format("expected %s, got %s (%s)", tostring(case.outcome),
        tostring(status), reason_of(detail)))
    -- The REASON, where the corpus states one. "No signature at all" and "a
    -- signature that did not check out" lead an operator to opposite actions,
    -- so a refusal with the wrong code is a defect even though the request is
    -- denied either way.
    if case.lua_refusal_reason then
      check(reason_of(detail) == case.lua_refusal_reason,
        "unsigned: " .. case.name .. " -> " .. case.lua_refusal_reason,
        "got " .. reason_of(detail))
    end
    unsigned_cases_run = unsigned_cases_run + 1
  end
elseif sig_group then
  -- Same discipline as the signed group below: the image build EXPORTS
  -- MUDRAID_CONFORMANCE_REQUIRE_SIGNATURE, so a harness there that cannot
  -- load the reader is a build failure. Elsewhere it is reported LOUDLY
  -- rather than passed over, because an unreported gap in coverage is how a
  -- conformance claim becomes broader than what was measured.
  if os.getenv("MUDRAID_CONFORMANCE_REQUIRE_SIGNATURE") then
    check(false, "the unsigned /decide response cases MUST run here",
      "decide.lua/cjson could not be loaded, and absence handling needs "
      .. "neither RS256 nor a network")
  else
    print("  NOT run here: the unsigned decide_response_signature cases — "
      .. "decide.lua needs cjson")
  end
end

if sig_group and ok_decide and rsa_available then
  local sig_cases = sig_group.cases
  check(#sig_cases >= 20, "the signature corpus is not empty")

  local expected = sig_group.expected
  local base_opts = {
    crypto = crypto,
    keys = sig_group.keys,
    expected = {
      platform_id = expected.platform_id,
      environment = expected.environment,
      canonical_resource_uri = expected.canonical_resource_uri,
      action_key = expected.action_key,
      bundle_version = expected.bundle_version,
    },
    now = sig_group.verification_now_epoch,
  }

  local genuine_run, refusals_run = 0, 0
  for _, case in ipairs(sig_cases) do
    -- signature_valid null marks the UNSIGNED cases. They are not skipped —
    -- they ran above, against decide.read_response, which is where absence is
    -- governed. Only this loop, the pure signature verifier, has nothing to
    -- do with them.
    if case.signature_valid ~= nil then
      local err = decide.verify_signature(case.response, base_opts)
      if case.signature_valid then
        genuine_run = genuine_run + 1
        check(err == nil, "signature: " .. case.name, err)
      else
        refusals_run = refusals_run + 1
        check(err ~= nil, "signature: " .. case.name,
          "a signature that must fail verified")
      end
      signature_cases_run = signature_cases_run + 1
    end
  end
  -- Coverage shape, not just non-emptiness: both genuine outcomes and a real
  -- body of refusals must have run, or a corpus regeneration that dropped the
  -- mutation vectors would still pass.
  check(genuine_run >= 2, "at least two genuine signed decisions verified")
  check(refusals_run >= 15, "at least fifteen signature refusals exercised")

  -- The rotation/bootstrap edge, a fact about the VERIFIER'S key set rather
  -- than about any response: a signed response with no published decision
  -- keys must refuse.
  local genuine
  for _, case in ipairs(sig_cases) do
    if case.signature_valid == true then genuine = case break end
  end
  local no_keys_err = decide.verify_signature(genuine.response, {
    crypto = crypto, keys = {},
    expected = base_opts.expected, now = base_opts.now,
  })
  check(no_keys_err ~= nil, "a signed response with no keys is refused")
elseif sig_group then
  if os.getenv("MUDRAID_CONFORMANCE_REQUIRE_SIGNATURE") then
    -- The image build EXPORTS this so the group can never silently stop
    -- running where it is supposed to run: a harness that cannot load the
    -- verifier there is a build failure, not a coverage note.
    check(false, "decide_response_signature MUST run in this environment",
      "decide.lua/crypto.lua could not be loaded")
  else
    -- The count is what is ACTUALLY left unrun, not the whole group: the
    -- unsigned cases ran above without RS256, and reporting them as skipped
    -- would understate coverage as surely as the reverse overstates it.
    print("  NOT run here: the SIGNED decide_response_signature cases ("
      .. (#sig_group.cases - unsigned_cases_run)
      .. " of " .. #sig_group.cases
      .. ") — RS256 needs the gateway image's resty.openssl; they run in "
      .. "the gateway image build gate")
  end
end

-- ── Coverage, printed so a divergence in what is CHECKED is visible ─────────
print(string.format(
  "\n  conformance corpus v%s — lua adapter: %d path, %d header, "
  .. "%d signature (%d signed, %d unsigned) = %d cases",
  corpus.corpus_version, #path_cases, #header_cases,
  signature_cases_run + unsigned_cases_run, signature_cases_run,
  unsigned_cases_run,
  #path_cases + #header_cases + signature_cases_run + unsigned_cases_run))

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
