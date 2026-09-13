-- mudraid-enforce plugin unit tests (EP-110-US-04).
--
-- Pure Lua (5.1+/LuaJIT), no busted/ngx/Kong required, covering the
-- testable plugin logic: canonical JSON serialization (byte-compatibility
-- with the control-plane signer), signed-bundle verification and refusal
-- paths, reserved-header stripping, exact matcher resolution, and the
-- bounded ack spool.
--
-- Run from the repo root:
--     lua  kong/tests/lua/test_mudraid_enforce.lua
--     luajit kong/tests/lua/test_mudraid_enforce.lua
-- Also executed inside the kong image build (kong/Dockerfile), where the
-- optional real-crypto vectors additionally run against OpenSSL.
--
-- The CANONICAL_VECTORS expected strings are duplicated in
-- kong/tests/test_mudraid_enforce_contract.py, which asserts that Python's
-- json.dumps(value, sort_keys=True, separators=(",", ":")) — the exact
-- serialization bundle_compiler.py signs — produces the same bytes.
-- Change them only in BOTH files.

package.path = "./?.lua;" .. package.path

local canonical = require "kong.plugins.mudraid-enforce.canonical"
local headers = require "kong.plugins.mudraid-enforce.headers"
local matcher = require "kong.plugins.mudraid-enforce.matcher"
local ack = require "kong.plugins.mudraid-enforce.ack"
local bundle = require "kong.plugins.mudraid-enforce.bundle"

-- Resolve the companion test beside this file in both checkout and image.
local test_source = debug.getinfo(1, "S").source
local test_dir = assert(test_source:match("^@(.*/)"), "test script directory unavailable")
dofile(test_dir .. "test_execution.lua")

local failures, tests = 0, 0


-- A decision timestamp that is fresh whenever the suite runs. A hard-coded
-- literal would pass today and fail silently in a month, which is the worst
-- way to learn that freshness is enforced.
local function fresh_decided_at()
  return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function check(cond, name, detail)
  tests = tests + 1
  if cond then
    print("ok   " .. name)
  else
    failures = failures + 1
    print("FAIL " .. name .. (detail and (" — " .. tostring(detail)) or ""))
  end
end

local function eq(actual, expected, name)
  check(actual == expected, name,
    string.format("expected %q got %q", tostring(expected), tostring(actual)))
end

-- ---------------------------------------------------------------------------
-- Canonical JSON — vectors shared with the Python contract test
-- ---------------------------------------------------------------------------

local NULL = setmetatable({}, { __tostring = function() return "null" end })
local ARRAY_MT = {}
local JOPTS = { null = NULL, array_mt = ARRAY_MT }
local function arr(t) return setmetatable(t or {}, ARRAY_MT) end

-- VECTOR IDs V1..V6 — keep in sync with test_mudraid_enforce_contract.py.
local CANONICAL_VECTORS = {
  { id = "V1", value = { b = 1, a = "x" },
    expected = '{"a":"x","b":1}' },
  { id = "V2", value = { s = "héllo ⚡" },
    expected = '{"s":"h\\u00e9llo \\u26a1"}' },
  { id = "V3", value = { t = 'a"b\\c\nd\te' },
    expected = '{"t":"a\\"b\\\\c\\nd\\te"}' },
  { id = "V4",
    value = { arr = arr({ 1, 2, 3 }), empty = arr(), obj = {},
              nul = NULL, t = true, f = false, neg = -42 },
    expected = '{"arr":[1,2,3],"empty":[],"f":false,"neg":-42,"nul":null,"obj":{},"t":true}' },
  { id = "V5", value = { e = "🙂" },
    expected = '{"e":"\\ud83d\\ude42"}' },
  { id = "V6",
    value = { outer = { z = arr({ { k = "v", a = 2 } }), a = "end" }, n = 1234567890123 },
    expected = '{"n":1234567890123,"outer":{"a":"end","z":[{"a":2,"k":"v"}]}}' },
}

for _, v in ipairs(CANONICAL_VECTORS) do
  local got = canonical.encode(v.value, JOPTS)
  eq(got, v.expected, "canonical " .. v.id)
end

-- Refusals: anything without a certain canonical form is an error, never a
-- guess (a lenient serializer would let a tampered bundle re-hash cleanly).
check(canonical.encode({ x = 1.5 }, JOPTS) == nil, "canonical refuses non-integer numbers")
check(canonical.encode({ x = 0 / 0 }, JOPTS) == nil, "canonical refuses NaN")
check(canonical.encode({ "a", x = "b" }, JOPTS) == nil, "canonical refuses mixed array/hash")
check(canonical.encode({ [true] = "x" }, JOPTS) == nil, "canonical refuses non-string keys")
check(canonical.encode({ f = print }, JOPTS) == nil, "canonical refuses functions")
check(canonical.encode({ s = "\255bad" }, JOPTS) == nil, "canonical refuses invalid UTF-8")

-- ---------------------------------------------------------------------------
-- Reserved-header stripping (A03-04)
-- ---------------------------------------------------------------------------

local prefixes = headers.effective_prefixes(nil)
check(headers.should_strip("x-mudraid-role", prefixes), "strip lowercase reserved header")
check(headers.should_strip("X-MudraID-Decision-Id", prefixes), "strip mixed-case reserved header")
check(headers.should_strip("X-MUDRAID-ANYTHING", prefixes), "strip uppercase reserved header")
check(not headers.should_strip("Authorization", prefixes), "keep Authorization")
check(not headers.should_strip("X-Correlation-ID", prefixes), "keep correlation header")

local widened = headers.effective_prefixes({ "X-Custom-Auth-" })
check(headers.should_strip("x-custom-auth-role", widened), "bundle can widen the strip list")
check(headers.should_strip("x-mudraid-role", widened), "bundle cannot drop the default floor")

-- ---------------------------------------------------------------------------
-- Exact matcher (A03-06/07)
-- ---------------------------------------------------------------------------

local idx = assert(matcher.build({
  { tool_name = "send_email", action_key = "email.send" },
  { tool_name = "Send_Email", action_key = "email.send.other" },
}))
check(matcher.resolve(idx, "send_email") ~= nil, "matcher exact hit")
eq(select(1, matcher.resolve(idx, "send_email")).action_key, "email.send", "matcher returns bound action")
check(matcher.resolve(idx, "Send_Email").action_key == "email.send.other",
  "matcher is case-sensitive (distinct names, distinct actions)")
local _, why = matcher.resolve(idx, "send_emailx")
eq(why, "unmapped", "matcher never fuzzy-matches")
local _, why2 = matcher.resolve(idx, "")
eq(why2, "invalid_name", "matcher refuses empty name")
local _, why3 = matcher.resolve(idx, string.rep("a", matcher.MAX_TOOL_NAME_LEN + 1))
eq(why3, "invalid_name", "matcher refuses oversized name")
local _, why4 = matcher.resolve(idx, 42)
eq(why4, "invalid_name", "matcher refuses non-string name")

local dup_idx, dup_err = matcher.build({
  { tool_name = "t" }, { tool_name = "t" },
})
check(dup_idx == nil and dup_err == "BUNDLE_MATCHER_AMBIGUOUS",
  "ambiguous corpus refused at build time")

-- ---------------------------------------------------------------------------
-- Bounded ack spool
-- ---------------------------------------------------------------------------

local spool = ack.new(3)
for i = 1, 5 do
  ack.push(spool, { n = i })
end
eq(ack.size(spool), 3, "spool bounded")
eq(spool.dropped, 2, "spool counts dropped reports (honest loss)")
eq(spool.items[1].n, 3, "spool drops OLDEST first")

local delivered = {}
local sent = ack.drain(spool, function(r)
  if r.n == 5 then return false end
  delivered[#delivered + 1] = r.n
  return true
end)
eq(sent, 2, "drain stops at first failure")
eq(ack.size(spool), 1, "failed report stays queued")
eq(delivered[1], 3, "drain preserves FIFO order")

-- ---------------------------------------------------------------------------
-- Bundle verification (A03-05) — injected fake crypto
-- ---------------------------------------------------------------------------

-- Deterministic fake digests (64 lowercase hex chars) so the verification
-- LOGIC is tested independently of OpenSSL; real algorithm vectors run in
-- the optional section below.
local function fake_hash(s, salt)
  local h = 5381 + salt
  for i = 1, #s do
    h = (h * 33 + s:byte(i)) % 4294967296
  end
  return string.rep(string.format("%08x", h), 8)
end
local fake_crypto = {
  sha256_hex = function(s) return fake_hash(s, 0) end,
  hmac_sha256_hex = function(key, s) return fake_hash(key .. "|" .. s, 1) end,
}

local SECRET = "test-signing-secret"

local function make_payload(version)
  return {
    schema_version = "1.0",
    bundle_version = version,
    issued_at = "2026-07-21T00:00:00+00:00",
    not_before = "2026-07-21T00:00:00+00:00",
    previous_bundle_version = NULL,
    content = {
      surface = {
        platform_id = "11111111-1111-1111-1111-111111111111",
        domain = "mcp.example.com",
        environment = "production",
        canonical_resource_uri = "https://mcp.example.com/mcp",
      },
      evaluation = {
        mode = "live",
        decide_required = true,
        on_timeout = "deny",
        on_error = "deny",
        on_unmapped_action = "deny",
        on_stale_bundle = "deny",
        forward = "once",
        retry_forwarded_request = false,
      },
      trusted_context = {
        strip_request_header_prefixes = arr({ "x-mudraid-" }),
        inject_after_enforcement_only = true,
      },
      matcher = {
        kind = "mcp_tool_exact",
        matcher_version = "1.0",
        actions = arr({
          {
            tool_name = "send_email",
            action_key = "email.send",
            action_version = 1,
            mapping_id = "22222222-2222-2222-2222-222222222222",
            mapping_revision = 3,
            risk_class = "high",
            evidence_class = "standard",
            required_scopes = arr(),
            failure_mode = "deny",
          },
        }),
      },
    },
  }
end

local function make_fetched(payload, secret)
  local canon = assert(canonical.encode(payload, JOPTS))
  return {
    bundle_version = payload.bundle_version,
    schema_version = payload.schema_version,
    payload = payload,
    payload_digest = fake_crypto.sha256_hex(canon),
    signing_key_id = "local-hmac-v1",
    signature = fake_crypto.hmac_sha256_hex(secret, canon),
  }
end

local function verify(fetched, opts_over)
  local opts = {
    crypto = fake_crypto,
    secret = SECRET,
    json = JOPTS,
    active = nil,
  }
  for k, v in pairs(opts_over or {}) do
    opts[k] = v
  end
  return bundle.verify(fetched, opts)
end

-- Happy path
local ok_bundle = select(1, verify(make_fetched(make_payload(3), SECRET)))
check(ok_bundle ~= nil, "valid signed bundle verifies")
if ok_bundle then
  eq(ok_bundle.bundle_version, 3, "verified bundle carries its version")
  check(type(ok_bundle.content_digest) == "string" and #ok_bundle.content_digest == 64,
    "content digest computed (dual-digest contract)")
  check(matcher.resolve(ok_bundle.matcher_index, "send_email") ~= nil,
    "verified bundle yields a usable matcher index")
  eq(ok_bundle.strip_prefixes[1], "x-mudraid-", "strip list is server-owned bundle data")
  check(not ok_bundle.no_change, "fresh bundle is not a no-op")
end

-- Tampered payload after signing -> digest mismatch
local tampered = make_fetched(make_payload(3), SECRET)
tampered.payload.content.matcher.actions[1].tool_name = "exfiltrate_everything"
local _, tcode = verify(tampered)
eq(tcode, "BUNDLE_DIGEST_MISMATCH", "tampered bundle refused (digest)")

-- Wrong signing key -> signature invalid
local _, wcode = verify(make_fetched(make_payload(3), "attacker-secret"))
eq(wcode, "BUNDLE_SIGNATURE_INVALID", "wrong-key signature refused")

-- Forged digest AND signature by an attacker without the secret
local forged = make_fetched(make_payload(3), SECRET)
forged.payload.content.matcher.actions[1].tool_name = "exfiltrate"
local fcanon = assert(canonical.encode(forged.payload, JOPTS))
forged.payload_digest = fake_crypto.sha256_hex(fcanon)
forged.signature = fake_crypto.hmac_sha256_hex("guessed-secret", fcanon)
local _, fcode = verify(forged)
eq(fcode, "BUNDLE_SIGNATURE_INVALID", "re-hashed forgery still refused (signature)")

-- No signing secret configured -> refuse (never trust unsigned)
local _, ncode = bundle.verify(make_fetched(make_payload(3), SECRET),
  { crypto = fake_crypto, secret = nil, json = JOPTS })
eq(ncode, "BUNDLE_SIGNING_SECRET_UNCONFIGURED", "unsigned trust refused without secret")
local _, ncode2 = verify(make_fetched(make_payload(3), SECRET), { secret = "" })
eq(ncode2, "BUNDLE_SIGNING_SECRET_UNCONFIGURED", "unsigned trust refused with empty secret")

-- ── The HMAC is no longer REQUIRED: RS256 alone is sufficient ────────────────
--
-- bundle_signing_secret is SYMMETRIC — anyone who can verify with it can also
-- sign with it — so a customer holding it could mint bundles for their own
-- surface. It was never shippable, and a customer adapter must verify with the
-- public key alone. These three cases are the whole rule.
do
  local asym_payload = make_payload(3)
  local asym = make_fetched(asym_payload, SECRET)
  asym.signature_value = "c2ln"          -- present; the stub decides validity
  asym.signature_key_id = "bundle-rs256-1"

  -- (a) RS256-ALONE ACCEPTANCE, which is the capability every customer
  --     deployment depends on: a bundle verified by the PUBLIC key with no
  --     shared secret configured anywhere.
  --
  --     The fixture is built to the shape verify_asymmetric actually reads —
  --     opts.verification_keys keyed by signature_key_id, a pinned profile and
  --     algorithm, and signature_claims that canonicalize and then match the
  --     bundle they claim to cover. An earlier attempt at this test was short
  --     of that, failed on its own construction, and would have had to be
  --     weakened until it passed, which would have asserted nothing.
  local PUBLIC_PEM = "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----"
  local KEY_ID = "bundle-rs256-1"

  -- A crypto stub that verifies ONLY the claim bytes the signer produced.
  -- Accepting anything would make every assertion below vacuous: the test
  -- would pass with the claims/payload binding removed from bundle.lua.
  local signed_claim_bytes
  local rs_ok = {}
  for k, v in pairs(fake_crypto) do rs_ok[k] = v end
  rs_ok.verify_rs256 = function(pem, message, raw)
    if pem ~= PUBLIC_PEM then return false, "wrong key" end
    if raw ~= "sig" then return false, "wrong signature bytes" end
    if message ~= signed_claim_bytes then return false, "signature does not verify" end
    return true
  end

  -- The bundle the server publishes once HMAC is retired: NO `signature` and
  -- NO `signing_key_id` at all. Those two fields were required
  -- unconditionally, so this exact response was refused as
  -- BUNDLE_RESPONSE_INVALID before any signature logic ran.
  local function make_rs256_only(version, mutate)
    local payload = make_payload(version)
    local canon = assert(canonical.encode(payload, JOPTS))
    local digest = fake_crypto.sha256_hex(canon)
    local fetched = {
      bundle_version = payload.bundle_version,
      schema_version = payload.schema_version,
      payload = payload,
      payload_digest = digest,
      signature_profile = bundle.SIGNATURE_PROFILE,
      signature_algorithm = bundle.SIGNATURE_ALGORITHM,
      signature_key_id = KEY_ID,
      signature_value = "c2ln",  -- base64("sig")
      signature_claims = {
        key_id = KEY_ID,
        payload_digest = digest,
        bundle_version = payload.bundle_version,
        platform_id = "plat-1",
        environment = "production",
      },
    }
    if mutate then mutate(fetched) end
    signed_claim_bytes = assert(canonical.encode(fetched.signature_claims, JOPTS))
    return fetched
  end

  local rs_opts = {
    crypto = rs_ok,
    secret = nil,                       -- THE POINT: no shared secret anywhere
    json = JOPTS,
    verification_keys = { [KEY_ID] = PUBLIC_PEM },
  }

  local accepted, acode, adetail = bundle.verify(make_rs256_only(3), rs_opts)
  check(accepted ~= nil,
    "RS256 alone verifies a bundle with no signing secret configured",
    tostring(acode) .. " " .. tostring(adetail))
  if accepted then
    eq(accepted.bundle_version, 3, "the RS256-verified bundle carries its version")
    check(matcher.resolve(accepted.matcher_index, "send_email") ~= nil,
      "the RS256-verified bundle yields a usable matcher index")
    -- handler.lua logs this key, and ngx.log raises on a nil argument. With no
    -- HMAC there is no HMAC key, so the key that authenticated the bundle is
    -- the asymmetric one — which is also the only honest answer to "which key
    -- vouched for what we applied".
    eq(accepted.signing_key_id, KEY_ID,
      "the verified bundle names the key that actually authenticated it")
  end

  -- Non-vacuity for the stub: the same fixture with a key the config does not
  -- publish must NOT verify. Without this, an over-permissive stub would make
  -- the acceptance above meaningless.
  local _, ukcode = bundle.verify(make_rs256_only(3),
    { crypto = rs_ok, secret = nil, json = JOPTS,
      verification_keys = { ["some-other-key"] = PUBLIC_PEM } })
  eq(ukcode, "BUNDLE_SIGNATURE_INVALID",
    "a signature naming an unpublished key is refused, not accepted for shape")

  -- The claims are compared to the bundle AFTER they verify. A signature over
  -- claims about a different payload proves MudraID signed something — not that
  -- it signed THIS.
  local _, mcode = bundle.verify(
    make_rs256_only(3, function(f) f.signature_claims.payload_digest = string.rep("a", 64) end),
    rs_opts)
  eq(mcode, "BUNDLE_SIGNATURE_INVALID",
    "a valid signature over claims about another payload does not cover this one")

  -- The algorithm is compared to a pinned constant, never read from the
  -- signature and used. A verifier that trusts this field verifies whatever
  -- the attacker chose.
  local _, algcode = bundle.verify(
    make_rs256_only(3, function(f) f.signature_algorithm = "none" end), rs_opts)
  eq(algcode, "BUNDLE_SIGNATURE_INVALID", "the signature algorithm is pinned, not read")

  -- A customer who still has the secret in their config must keep working when
  -- the control plane stops emitting HMAC. Before this, the configured secret
  -- was compared against a nil signature, so every RS256 bundle was refused as
  -- an HMAC failure — a deny attributed to the wrong signature entirely, on a
  -- gateway whose configuration nobody had touched.
  local kept, kcode = bundle.verify(make_rs256_only(3),
    { crypto = rs_ok, secret = SECRET, json = JOPTS,
      verification_keys = { [KEY_ID] = PUBLIC_PEM } })
  check(kept ~= nil,
    "a leftover HMAC secret does not refuse an RS256-only bundle", tostring(kcode))

  -- ...and the reverse is still closed: no signature of either kind, with a
  -- secret configured, is refused rather than treated as "nothing to check".
  local _, bothless = bundle.verify(
    make_rs256_only(3, function(f) f.signature_value = nil end),
    { crypto = rs_ok, secret = SECRET, json = JOPTS,
      verification_keys = { [KEY_ID] = PUBLIC_PEM } })
  eq(bothless, "BUNDLE_SIGNING_SECRET_UNCONFIGURED",
    "a configured secret with nothing to check is still unsigned trust")

  -- Present-but-malformed HMAC is still a refusal. Absence became allowed
  -- above; invalidity must not have come along with it.
  local _, malformed = bundle.verify(
    make_rs256_only(3, function(f) f.signature = "not-hex" end), rs_opts)
  eq(malformed, "BUNDLE_RESPONSE_INVALID",
    "a present-but-malformed HMAC signature is still refused")

  -- (b) REFUSED when the asymmetric signature is present and does NOT verify,
  --     EVEN THOUGH a valid HMAC secret is supplied. Present-but-invalid must
  --     never fall back to the weaker check: an attacker holding either key
  --     could otherwise corrupt a field and downgrade every bundle.
  local rs_bad = {}
  for k, v in pairs(fake_crypto) do rs_bad[k] = v end
  rs_bad.verify_rs256 = function() return false, "signature does not verify" end
  local _, dcode = bundle.verify(asym,
    { crypto = rs_bad, secret = SECRET, json = JOPTS,
      public_key_pem = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----" })
  eq(dcode, "BUNDLE_SIGNATURE_INVALID",
    "a present-but-invalid RS256 signature never downgrades to the HMAC")

  -- (c) Still REFUSED when neither is available — the rule is "at least one",
  --     not "HMAC optional".
  local _, ncode3 = bundle.verify(make_fetched(make_payload(3), SECRET),
    { crypto = fake_crypto, secret = nil, json = JOPTS })
  eq(ncode3, "BUNDLE_SIGNING_SECRET_UNCONFIGURED",
    "neither signature available is still unsigned trust, still refused")
end

-- Unsupported schema version
local sp = make_payload(3)
sp.schema_version = "9.9"
local sf = make_fetched(sp, SECRET)
sf.schema_version = "9.9"
local _, scode = verify(sf)
eq(scode, "BUNDLE_SCHEMA_UNSUPPORTED", "unknown schema version refused")

-- Envelope/payload version disagreement
local ef = make_fetched(make_payload(3), SECRET)
ef.bundle_version = 4
local _, ecode = verify(ef)
eq(ecode, "BUNDLE_ENVELOPE_MISMATCH", "envelope/payload version disagreement refused")

-- AUDIT-006 M4 — surface binding contract.
--
-- content.surface is the ONLY channel through which handler.lua learns the
-- environment and canonical resource URI it forwards on the /decide envelope.
-- Enforcement binds authority to exactly that pair (AUDIT-006 M3 item 2), so a
-- bundle that leaves either unbound describes a surface on which every request
-- deny-closes. Refused at activation rather than discovered at request time.
local function surface_case(mutate, name)
  local p = make_payload(3)
  mutate(p.content.surface)
  local _, code = verify(make_fetched(p, SECRET))
  eq(code, "BUNDLE_SURFACE_UNBOUND", name)
end
-- One dimension varies per case.
surface_case(function(s) s.canonical_resource_uri = nil end,
  "absent canonical_resource_uri refused")
surface_case(function(s) s.canonical_resource_uri = NULL end,
  "JSON-null canonical_resource_uri refused (null sentinel is truthy in Lua)")
surface_case(function(s) s.canonical_resource_uri = "" end,
  "empty canonical_resource_uri refused")
surface_case(function(s) s.canonical_resource_uri = "   " end,
  "blank canonical_resource_uri refused")
surface_case(function(s) s.environment = nil end, "absent environment refused")
surface_case(function(s) s.environment = NULL end, "JSON-null environment refused")
surface_case(function(s) s.platform_id = nil end, "absent platform_id refused")
local nosurface = make_payload(3)
nosurface.content.surface = nil
local _, nscode = verify(make_fetched(nosurface, SECRET))
eq(nscode, "BUNDLE_SURFACE_UNBOUND", "bundle with no surface at all refused")

-- Paired positive: a bound surface still activates and still yields the exact
-- values the handler forwards (the refusal suppresses, it does not remove).
local bound = select(1, verify(make_fetched(make_payload(3), SECRET)))
check(bound ~= nil, "bound surface still verifies")
if bound then
  local s = bound.payload.content.surface
  eq(s.environment, "production", "verified bundle carries the surface environment")
  eq(s.canonical_resource_uri, "https://mcp.example.com/mcp",
    "verified bundle carries the canonical resource uri")
end

-- `domain` is descriptive, not part of the authority binding: its absence must
-- NOT refuse the bundle (the guard is exactly as wide as it needs to be).
local nodomain = make_payload(3)
nodomain.content.surface.domain = nil
check(select(1, verify(make_fetched(nodomain, SECRET))) ~= nil,
  "absent surface.domain does not refuse the bundle")

-- Evaluation contract violations are refused, never downgraded
local function eval_case(mutate, name)
  local p = make_payload(3)
  mutate(p.content.evaluation)
  local _, code = verify(make_fetched(p, SECRET))
  eq(code, "BUNDLE_EVALUATION_UNSUPPORTED", name)
end
eval_case(function(e) e.on_timeout = "allow" end, "on_timeout=allow refused")
eval_case(function(e) e.decide_required = false end, "decide_required=false refused (no snapshot support)")
eval_case(function(e) e.forward = "retry" end, "forward!=once refused")
eval_case(function(e) e.retry_forwarded_request = true end, "retry_forwarded_request=true refused")
eval_case(function(e) e.mode = "observe" end, "unknown evaluation mode refused")

-- Matcher contract
local mp = make_payload(3)
mp.content.matcher.kind = "mcp_tool_fuzzy"
local _, mcode = verify(make_fetched(mp, SECRET))
eq(mcode, "BUNDLE_MATCHER_UNSUPPORTED", "non-exact matcher kind refused")

local ap = make_payload(3)
ap.content.matcher.actions = arr()
local _, acode = verify(make_fetched(ap, SECRET))
eq(acode, "BUNDLE_CONTENT_INVALID", "empty action corpus refused")

local dp = make_payload(3)
local dup = {}
for k, v in pairs(dp.content.matcher.actions[1]) do dup[k] = v end
dp.content.matcher.actions[2] = dup
local _, dcode = verify(make_fetched(dp, SECRET))
eq(dcode, "BUNDLE_MATCHER_AMBIGUOUS", "duplicate tool_name refused")

-- Monotonic version rules vs the active bundle
local active = { bundle_version = 5, payload_digest = fake_crypto.sha256_hex("old") }
local _, rcode = verify(make_fetched(make_payload(3), SECRET), { active = active })
eq(rcode, "BUNDLE_VERSION_REGRESSION", "version regression refused")

local same_v = make_fetched(make_payload(5), SECRET)
local _, ccode = verify(same_v, { active = { bundle_version = 5, payload_digest = string.rep("0", 64) } })
eq(ccode, "BUNDLE_VERSION_CONFLICT", "same version, different bytes refused")

local noop = select(1, verify(same_v,
  { active = { bundle_version = 5, payload_digest = same_v.payload_digest } }))
check(noop ~= nil and noop.no_change, "same version, same digest is a verified no-op")

-- ---------------------------------------------------------------------------
-- /decide client authentication handshake (deny-closed on the credential).
-- decide.lua requires cjson.safe; run these only where it loads (the gateway
-- image and any env with lua-cjson). resty.http is injected, never called for
-- real, so no network is needed.
-- ---------------------------------------------------------------------------

local ok_decide, decide = pcall(require, "kong.plugins.mudraid-enforce.decide")
if ok_decide then
  -- (1) base_url configured but NO adapter token -> deny-closed, and the
  -- request is never even attempted anonymously. The credential is now this
  -- adapter's own bearer, never MudraID's shared workload secret.
  local attempted = false
  decide._http = { new = function() attempted = true; return {} end }
  local o_missing, d_missing = decide.call(
    { base_url = "https://api.example.test", decide_timeout_ms = 1000 },
    { correlation_id = "corr-missing" })
  eq(o_missing, "error", "decide denies when the adapter token is unconfigured")
  eq(d_missing.reason, "DECIDE_CREDENTIAL_UNCONFIGURED",
    "typed credential-missing reason (deny-closed)")
  check(not attempted, "no /decide request is attempted without a credential")

  -- (2) an empty-string token is unconfigured (never sent blank).
  local o_empty = decide.call(
    { base_url = "https://api.example.test", decide_timeout_ms = 1000, adapter_token = "" },
    { correlation_id = "corr-empty" })
  eq(o_empty, "error", "an empty adapter token is deny-closed too")

  -- (3) with a token -> Authorization: Bearer is attached, and the request
  -- goes to the PUBLIC adapter channel derived from base_url.
  local captured
  decide._http = { new = function()
    return {
      set_timeout = function() end,
      request_uri = function(_, request_url, opts)
        -- The URL is captured, not discarded: the whole point of deriving from
        -- base_url is WHERE the request goes, and a mock that drops it cannot
        -- tell the public channel from the internal one.
        captured = opts
        captured.url = request_url
        -- A CONTRACT-VALID response: versioned, and bound to the decision id
        -- this very call sent. A bare {"decision":"allow"} is refused below.
        return { status = 200, body =
          '{"schema_version":"2.0","decision_id":"dec-ok","decision":"allow","decided_at":"'
          .. fresh_decided_at() .. '"}' }
      end,
    }
  end }
  local o_ok = decide.call(
    { base_url = "https://api.example.test", decide_timeout_ms = 1000, adapter_token = "adapter-tok" },
    { correlation_id = "corr-ok", decision_id = "dec-ok" })
  eq(o_ok, "allow", "authenticated /decide call proceeds to a decision")
  check(captured ~= nil and captured.headers ~= nil, "request issued with headers")
  if captured and captured.headers then
    eq(captured.headers["Authorization"], "Bearer adapter-tok",
      "the adapter's own bearer is presented, not a shared workload secret")
    -- THE ASSERTION THIS CHANGE EXISTS FOR. MudraID's internal service secret
    -- is shared by every gateway and names no tenant; a customer holding it
    -- could call the private enforcement route as us. It must not appear on a
    -- customer-installable adapter's request at all.
    check(captured.headers["X-Service-Secret"] == nil,
      "no internal service secret on the customer channel")
    eq(captured.url, "https://api.example.test/api/v1/adapter/enforcement/decide",
      "the call goes to the PUBLIC adapter channel derived from base_url")
    eq(captured.headers["Content-Type"], "application/json",
      "content-type preserved alongside the credential")
  end

  -- (4) server rejects the credential (401/403) -> mapped to error -> deny.
  decide._http = { new = function()
    return {
      set_timeout = function() end,
      request_uri = function() return { status = 401, body = "" } end,
    }
  end }
  local o_401, d_401 = decide.call(
    { base_url = "https://api.example.test", decide_timeout_ms = 1000, adapter_token = "revoked-tok" },
    { correlation_id = "corr-401" })
  eq(o_401, "error", "server 401 (bad credential) is deny-closed")
  eq(d_401.reason, "DECIDE_STATUS_401", "typed status reason for rejected credential")

  -- (5) response validation. Each case answers 200 with a body that is wrong in
  -- exactly one way, and every one of them must deny-close. A 200 is not a
  -- decision; a readable, bound decision is.
  local function answering(body)
    decide._http = { new = function()
      return {
        set_timeout = function() end,
        request_uri = function() return { status = 200, body = body } end,
      }
    end }
    local outcome, detail = decide.call(
      { base_url = "https://api.example.test", decide_timeout_ms = 1000, adapter_token = "adapter-tok" },
      { correlation_id = "corr-v", decision_id = "dec-expected" })
    return outcome, detail
  end

  local o_bare, d_bare = answering('{"decision":"allow"}')
  eq(o_bare, "error", "a bare allow is not a readable answer")
  eq(d_bare.reason, "DECIDE_RESPONSE_SCHEMA_UNSUPPORTED",
    "an unversioned response is refused on the version, first")

  local o_ver = answering('{"schema_version":"9.9","decision_id":"dec-expected","decision":"allow"}')
  eq(o_ver, "error", "an unsupported response version is refused")

  local o_noid = answering('{"schema_version":"2.0","decision":"allow"}')
  eq(o_noid, "error", "a response with no decision_id is refused")

  local o_mis, d_mis = answering(
    '{"schema_version":"2.0","decision_id":"some-other","decision":"allow"}')
  eq(o_mis, "error", "an allow bound to a DIFFERENT request is refused")
  eq(d_mis.reason, "DECIDE_RESPONSE_DECISION_ID_MISMATCH",
    "the mismatch is named, because it is the replay case")

  local o_word = answering(
    '{"schema_version":"2.0","decision_id":"dec-expected","decision":"maybe"}')
  eq(o_word, "error", "an unrecognised decision word is never optimistically read")

  local o_big, d_big = answering(
    '{"schema_version":"2.0","decision_id":"dec-expected","decision":"allow","pad":"'
    .. string.rep("x", 70000) .. '"}')
  eq(o_big, "error", "an oversized response is refused before it is parsed")
  eq(d_big.reason, "DECIDE_RESPONSE_OVERSIZED", "refused on size, not on content")

  local o_good = answering(
    '{"schema_version":"2.0","decision_id":"dec-expected","decision":"deny","decided_at":"'
      .. fresh_decided_at() .. '"}')
  eq(o_good, "deny", "a valid, bound deny is read as a deny")

  -- (6) response SIGNATURE handling (A9-02). Structural/binding refusals are
  -- pure Lua, so a fake verify_rs256 exercises them here; the REAL RS256
  -- vectors run in test_conformance.lua inside the gateway image, where the
  -- OpenSSL bindings exist.
  local function answering_with_opts(body, verify_opts)
    decide._http = { new = function()
      return {
        set_timeout = function() end,
        request_uri = function() return { status = 200, body = body } end,
      }
    end }
    return decide.call(
      { base_url = "https://api.example.test", decide_timeout_ms = 1000,
        adapter_token = "adapter-tok" },
      { correlation_id = "corr-sig", decision_id = "dec-expected" },
      verify_opts)
  end

  local stamp = fresh_decided_at()
  local function signed_body(sig_json)
    return '{"schema_version":"2.0","decision_id":"dec-expected","decision":"allow",'
      .. '"decided_at":"' .. stamp .. '","signature":' .. sig_json .. '}'
  end
  local trusting_crypto = { verify_rs256 = function() return true end }
  local refusing_crypto = { verify_rs256 = function() return false, "bad sig" end }
  -- The SAME null sentinel decide.lua's decoder produces — handler.lua passes
  -- channel.null for exactly this reason. A different sentinel would make the
  -- null-signature cases below vacuous.
  local ok_cjson, cjson_lib = pcall(require, "cjson.safe")
  local cjson_null = ok_cjson and cjson_lib.null or nil
  local function claims_json(overrides)
    local now = os.time()
    local c = {
      profile = '"mudraid.decision.signature/1"',
      algorithm = '"RS256"',
      key_id = '"k1"',
      decision_id = '"dec-expected"',
      decision = '"allow"',
      decided_at = '"' .. stamp .. '"',
      not_before = '"' .. os.date("!%Y-%m-%dT%H:%M:%SZ", now - 10) .. '"',
      expires_at = '"' .. os.date("!%Y-%m-%dT%H:%M:%SZ", now + 300) .. '"',
    }
    for k, v in pairs(overrides or {}) do c[k] = v end
    local parts = {}
    for k, v in pairs(c) do parts[#parts + 1] = '"' .. k .. '":' .. v end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  local function sig_json(claims, overrides)
    local s = {
      profile = '"mudraid.decision.signature/1"',
      algorithm = '"RS256"',
      key_id = '"k1"',
      claims = claims,
      signature = '"c2ln"',
    }
    for k, v in pairs(overrides or {}) do s[k] = v end
    local parts = {}
    for k, v in pairs(s) do parts[#parts + 1] = '"' .. k .. '":' .. v end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  local keys = { k1 = "-----BEGIN PUBLIC KEY-----fake" }

  -- A present signature with NO verification context is refused, never
  -- optimistically read: an unverifiable signature is not an absent one.
  local o_noopts, d_noopts = answering_with_opts(signed_body(sig_json(claims_json())), nil)
  eq(o_noopts, "error", "a signed response with no verify context is refused")
  eq(d_noopts.reason, "DECIDE_RESPONSE_SIGNATURE_INVALID",
    "refused as a signature fact, deny-closed")

  -- A present signature with keys and a verifier that accepts → read normally.
  local o_signed = answering_with_opts(signed_body(sig_json(claims_json())),
    { crypto = trusting_crypto, keys = keys })
  eq(o_signed, "allow", "a verifying signature lets the bound allow through")

  local exact_opts = { crypto = trusting_crypto, keys = keys, require_signed = true,
    expected = { execution_request_digest = string.rep("a", 64) } }
  local o_exact = answering_with_opts(signed_body(sig_json(claims_json({
    execution_request_digest = '"' .. string.rep("a", 64) .. '"' }))), exact_opts)
  eq(o_exact, "allow", "signed exact execution digest allows")
  local o_wrong_execution = answering_with_opts(signed_body(sig_json(claims_json({
    execution_request_digest = '"' .. string.rep("b", 64) .. '"' }))), exact_opts)
  eq(o_wrong_execution, "error", "another signed execution digest refuses")
  local o_missing_execution = answering_with_opts(signed_body(sig_json(claims_json())), exact_opts)
  eq(o_missing_execution, "error", "missing signed execution digest refuses")

  -- The verifier refusing the bytes refuses the response whole.
  local o_badsig = answering_with_opts(signed_body(sig_json(claims_json())),
    { crypto = refusing_crypto, keys = keys })
  eq(o_badsig, "error", "a signature the crypto refuses deny-closes the response")

  -- Unknown key (rotation refusal), pinned algorithm, claims/envelope drift
  -- and foreign-surface binding — each refused on its own fact.
  local o_unknown = answering_with_opts(signed_body(sig_json(claims_json())),
    { crypto = trusting_crypto, keys = {} })
  eq(o_unknown, "error", "a signature naming an unpublished key is refused")

  local o_alg = answering_with_opts(
    signed_body(sig_json(claims_json(), { algorithm = '"none"' })),
    { crypto = trusting_crypto, keys = keys })
  eq(o_alg, "error", "algorithm none is refused on the pinned constant")

  local o_flip = answering_with_opts(
    signed_body(sig_json(claims_json({ decision = '"deny"' }))),
    { crypto = trusting_crypto, keys = keys })
  eq(o_flip, "error", "claims disagreeing with the envelope decision are refused")

  local o_surface = answering_with_opts(
    signed_body(sig_json(claims_json({ platform_id = '"platform-other"' }))),
    { crypto = trusting_crypto, keys = keys,
      expected = { platform_id = "platform-mine" } })
  eq(o_surface, "error", "a decision bound to another platform is refused")

  local o_expired = answering_with_opts(
    signed_body(sig_json(claims_json({
      expires_at = '"2020-01-01T00:00:00Z"',
      not_before = '"2019-01-01T00:00:00Z"',
    }))),
    { crypto = trusting_crypto, keys = keys })
  eq(o_expired, "error", "an expired signature window is refused")

  -- Absent signature: read exactly as before (verify-when-present), even with
  -- a verify context wired — activation is the authority's move, not ours.
  local o_unsigned = answering_with_opts(
    '{"schema_version":"2.0","decision_id":"dec-expected","decision":"deny","decided_at":"'
      .. stamp .. '"}',
    { crypto = trusting_crypto, keys = keys })
  eq(o_unsigned, "deny", "an unsigned response is still read (verify-when-present)")

  -- (7) MANDATORY SIGNATURE MODE (conf.require_signed_decisions, reaching
  -- decide.lua as verify_opts.require_signed).
  --
  -- The equivalent of the Python middleware's `require_signed_decisions`.
  -- Verify-when-present is a ROLLOUT posture, not the destination: once the
  -- authority signs every response for a surface, an UNSIGNED response there
  -- is a stripped signature, and reading it is the exact hole the signature
  -- exists to close. The setting is what lets an operator say "signing is
  -- live here" — it is a config value, never a build-time constant, because
  -- the two adapters and the fleet reach that point at different moments.
  --
  -- It is deliberately ONE branch: the mode decides what an ABSENT signature
  -- means and nothing else. A PRESENT signature is verified identically in
  -- both modes, and every failure is deny-closed in both.
  local unsigned_body =
    '{"schema_version":"2.0","decision_id":"dec-expected","decision":"allow","decided_at":"'
    .. stamp .. '"}'

  -- OFF (the default) — unchanged: the unsigned response is still read.
  local o_off = answering_with_opts(unsigned_body,
    { crypto = trusting_crypto, keys = keys, require_signed = false })
  eq(o_off, "allow", "unsigned is accepted while signatures are not required")

  -- Absent is the same as explicitly false: an operator who has never heard
  -- of the setting gets the rollout posture, not a surprise flag day.
  local o_absent_conf = answering_with_opts(unsigned_body,
    { crypto = trusting_crypto, keys = keys })
  eq(o_absent_conf, "allow", "an unset requirement reads as not required")

  -- ON — an unsigned decision is refused, and refused as its OWN typed fact:
  -- "no signature at all" is a different operational failure from "a
  -- signature that did not check out", and an operator chasing a stalled
  -- rollout needs to tell them apart in the log.
  local o_on, d_on = answering_with_opts(unsigned_body,
    { crypto = trusting_crypto, keys = keys, require_signed = true })
  eq(o_on, "error", "an unsigned decision is refused when signatures are required")
  eq(d_on.reason, "DECIDE_RESPONSE_SIGNATURE_REQUIRED",
    "the refusal names the missing signature, not a generic invalid one")

  -- A JSON null signature is ABSENCE, not a present-and-broken signature.
  -- cjson decodes null to a sentinel, so a mode that only checked `== nil`
  -- would read `"signature": null` as present and refuse it with the wrong
  -- reason — or worse, on the OFF path, try to verify it.
  local o_null_on, d_null_on = answering_with_opts(
    '{"schema_version":"2.0","decision_id":"dec-expected","decision":"allow","decided_at":"'
      .. stamp .. '","signature":null}',
    { crypto = trusting_crypto, keys = keys, require_signed = true,
      json = { null = cjson_null } })
  eq(o_null_on, "error", "a null signature is absent, and absent is refused when required")
  eq(d_null_on.reason, "DECIDE_RESPONSE_SIGNATURE_REQUIRED",
    "a null signature is refused as missing, not as invalid")

  -- Requiring signatures must not break the case it exists to reach: a
  -- genuine signature still lets the bound decision through.
  local o_on_signed = answering_with_opts(signed_body(sig_json(claims_json())),
    { crypto = trusting_crypto, keys = keys, require_signed = true })
  eq(o_on_signed, "allow", "a verifying signature is read normally in mandatory mode")

  -- INVALID IN BOTH MODES. The mode governs absence only; a present
  -- signature that fails is refused whether or not signatures are required,
  -- and the reason stays the signature-invalid one. Turning the requirement
  -- OFF must never become a way to get a bad signature accepted.
  local bad_body = signed_body(sig_json(claims_json()))
  local o_bad_off, d_bad_off = answering_with_opts(bad_body,
    { crypto = refusing_crypto, keys = keys, require_signed = false })
  eq(o_bad_off, "error", "an invalid signature is refused with the requirement off")
  eq(d_bad_off.reason, "DECIDE_RESPONSE_SIGNATURE_INVALID",
    "refused as an invalid signature, off")
  local o_bad_on, d_bad_on = answering_with_opts(bad_body,
    { crypto = refusing_crypto, keys = keys, require_signed = true })
  eq(o_bad_on, "error", "an invalid signature is refused with the requirement on")
  eq(d_bad_on.reason, "DECIDE_RESPONSE_SIGNATURE_INVALID",
    "refused as an invalid signature, on")
  -- Unknown key and an expired window are signature facts too, not absence:
  -- both keep their own refusal in mandatory mode.
  local o_unknown_on, d_unknown_on = answering_with_opts(
    signed_body(sig_json(claims_json())),
    { crypto = trusting_crypto, keys = {}, require_signed = true })
  eq(o_unknown_on, "error", "an unknown-key signature is refused in mandatory mode")
  eq(d_unknown_on.reason, "DECIDE_RESPONSE_SIGNATURE_INVALID",
    "an unknown key is a signature failure, not a missing signature")
  local o_expired_on, d_expired_on = answering_with_opts(
    signed_body(sig_json(claims_json({
      expires_at = '"2020-01-01T00:00:00Z"',
      not_before = '"2019-01-01T00:00:00Z"',
    }))),
    { crypto = trusting_crypto, keys = keys, require_signed = true })
  eq(o_expired_on, "error", "an expired signature is refused in mandatory mode")
  eq(d_expired_on.reason, "DECIDE_RESPONSE_SIGNATURE_INVALID",
    "an expired window is a signature failure, not a missing signature")

  -- THE MODE IS CONFINED TO THE SIGNATURE BRANCH.
  --
  -- The Kong plugin has NO V1 mode to leave alone — `mode="v1"` is the Python
  -- middleware's static route-scope path (middleware.py); this plugin only
  -- ever speaks V2, and its /decide reader accepts exactly the "2.0" response
  -- contract. The equivalent claim here is that turning the requirement on
  -- changes nothing except what an absent signature means: a response that
  -- was already unreadable stays unreadable FOR ITS ORIGINAL REASON, never
  -- relabelled as a signature problem.
  local o_v1ish, d_v1ish = answering_with_opts(
    '{"schema_version":"1.0","decision_id":"dec-expected","decision":"allow","decided_at":"'
      .. stamp .. '"}',
    { crypto = trusting_crypto, keys = keys, require_signed = true })
  eq(o_v1ish, "error", "a non-2.0 response contract is still refused on the contract")
  eq(d_v1ish.reason, "DECIDE_RESPONSE_SCHEMA_UNSUPPORTED",
    "refused on the response contract, not relabelled a signature failure")
  local o_mis_on, d_mis_on = answering_with_opts(
    '{"schema_version":"2.0","decision_id":"some-other","decision":"allow","decided_at":"'
      .. stamp .. '"}',
    { crypto = trusting_crypto, keys = keys, require_signed = true })
  eq(o_mis_on, "error", "an unbound response is still refused on the binding")
  eq(d_mis_on.reason, "DECIDE_RESPONSE_DECISION_ID_MISMATCH",
    "the binding refusal survives mandatory mode unchanged")

  decide._http = nil
else
  print("skip decide.lua auth tests (cjson/resty unavailable outside the gateway image)")
end

-- ---------------------------------------------------------------------------
-- Boundary-execution receipt producer (EP-510 §11.5, step 3)
--
-- The receipt says what the BOUNDARY did. These tests exercise every terminal
-- path the handler can take, because the whole value of the artifact is that
-- "forwarded once" and "did not forward" are the same kind of statement made
-- about the same kind of request — a producer that only knew about the happy
-- path would be a record of successes, and a store that can only hold
-- successes cannot be a proof source.
--
-- RECEIPT_CANONICAL_VECTOR is duplicated in
-- kong/tests/test_mudraid_enforce_contract.py, which recomputes it from
-- mudraid_contracts.boundary_receipt.canonical_receipt_bytes. Change it only
-- in BOTH files.
-- ---------------------------------------------------------------------------

local receipt = require "kong.plugins.mudraid-enforce.receipt"

local RECEIPT_CANONICAL_VECTOR =
  '{"action_id":"action.send_payment","action_version":"3",' ..
  '"adapter_type":"kong_mudraid_enforce","adapter_version":"0.1.0",' ..
  '"authoritative_decision":"allow","authoritative_directive":"forward_once",' ..
  '"boundary_outcome":"forwarded_once","boundary_outcome_reason":"",' ..
  '"bundle_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",' ..
  '"bundle_version":7,"canonical_resource_uri":"mcp://payments/send",' ..
  '"correlation_id":"corr-vector",' ..
  '"decision_id":"11111111-2222-3333-4444-555555555555",' ..
  '"enforcement_boundary_name":"","environment":"production","forwarded_count":1,' ..
  '"observed_at":"2026-07-27T00:00:00Z","organization_id":"","platform_id":"platform_1",' ..
  '"proof_scope_digest":"","receipt_id":"rcpt-vector-1","receipt_schema_version":"1.0.0"}'

local function receipt_ctx(overrides)
  local ctx = {
    receipt_id = "rcpt-vector-1",
    observed_at = "2026-07-27T00:00:00Z",
    decision_id = "11111111-2222-3333-4444-555555555555",
    correlation_id = "corr-vector",
    adapter_type = "kong_mudraid_enforce",
    adapter_version = "0.1.0",
    surface = {
      platform_id = "platform_1",
      environment = "production",
      canonical_resource_uri = "mcp://payments/send",
    },
    bundle = { version = 7, payload_digest = string.rep("b", 64) },
    action = { action_key = "action.send_payment", action_version = 3 },
  }
  for k, v in pairs(overrides or {}) do
    ctx[k] = v
  end
  return ctx
end

-- The forward path: the ONLY path in this plugin that produces a 1.
local fwd = receipt.mint(receipt_ctx())
check(fwd ~= nil, "forward path mints a receipt")
eq(fwd.boundary_outcome, "forwarded_once", "forward outcome word")
eq(fwd.forwarded_count, 1, "forward count is exactly one")
eq(fwd.boundary_outcome_reason, "", "the forward path is the only one with no reason")
eq(fwd.authoritative_decision, "allow", "a forward records the allow it was made under")
eq(fwd.authoritative_directive, "forward_once", "directive follows the decision")
eq(fwd.action_version, "3", "action_version is stringified to match the scope contract")
eq(receipt.canonical(fwd), RECEIPT_CANONICAL_VECTOR,
  "canonical receipt bytes match the Python contract vector")

-- Honest incompleteness: the three fields the boundary cannot produce are
-- emitted ABSENT, never approximated. The reader's refusal names them.
eq(fwd.organization_id, "", "the boundary never learns the tenant")
eq(fwd.proof_scope_digest, "", "no scope digest is distributed to an adapter")
eq(fwd.enforcement_boundary_name, "", "nothing names the boundary a request traversed")

-- Every refusal the handler can emit forwards nothing, and each carries the
-- outcome word its reason entails.
local EXPECTED_REASON_OUTCOMES = {
  ENFORCE_ACTION_UNMAPPED = "blocked",
  ENFORCE_BATCH_UNSUPPORTED = "blocked",
  ENFORCE_BODY_TOO_LARGE = "blocked",
  ENFORCE_BODY_UNREADABLE = "blocked",
  ENFORCE_MALFORMED_REQUEST = "blocked",
  ENFORCE_MESSAGE_NOT_ALLOWED = "blocked",
  ENFORCE_METHOD_NOT_ALLOWED = "blocked",
  ENFORCE_DECISION_DENY = "blocked",
  ENFORCE_NO_VALID_BUNDLE = "failed_closed",
  ENFORCE_DECIDE_UNAVAILABLE = "failed_closed",
  ENFORCE_FORWARD_ONCE_UNAVAILABLE = "failed_closed",
}
local reason_count = 0
for reason, expected_outcome in pairs(EXPECTED_REASON_OUTCOMES) do
  reason_count = reason_count + 1
  local r, err = receipt.mint(receipt_ctx({ reason = reason }))
  check(r ~= nil, "mint " .. reason, err)
  if r then
    eq(r.boundary_outcome, expected_outcome, reason .. " outcome word")
    eq(r.forwarded_count, 0, reason .. " forwards nothing")
    eq(r.boundary_outcome_reason, reason, reason .. " records its own reason")
  end
end
eq(reason_count, 11, "every typed refusal in handler.lua has a receipt mapping")

-- Rule R7, enforced by the PRODUCER and not only by the reader: a pre-/decide
-- refusal carries no decision facts even when a caller supplies a decision id.
-- Honouring one would create the appearance of a decision for a request no
-- decision was made about.
local unmapped = receipt.mint(receipt_ctx({ reason = "ENFORCE_ACTION_UNMAPPED" }))
eq(unmapped.decision_id, "", "R7: a pre-/decide refusal drops a supplied decision id")
eq(unmapped.authoritative_decision, "", "R7: no decision exists before /decide")
eq(unmapped.authoritative_directive, "", "R7: no directive exists before /decide")

-- ENFORCE_BODY_UNREADABLE is a pre-/decide reason the merged proposal's R7
-- enumeration omits. Under R7 as written this truthful receipt would score
-- MALFORMED and a correct refusal would read as a proof defect.
local unreadable = receipt.mint(receipt_ctx({ reason = "ENFORCE_BODY_UNREADABLE" }))
eq(unreadable.decision_id, "", "ENFORCE_BODY_UNREADABLE is a pre-/decide reason")

-- Post-/decide refusals keep the decision id and record the decision they were
-- made under, taken from the branch actually taken — never inferred.
local denied = receipt.mint(receipt_ctx({ reason = "ENFORCE_DECISION_DENY" }))
eq(denied.decision_id, "11111111-2222-3333-4444-555555555555",
  "a post-/decide refusal keeps its decision id")
eq(denied.authoritative_decision, "deny", "deny is recorded, not inferred from the outcome")
eq(denied.authoritative_directive, "block", "directive follows the decision")

local unsafe = receipt.mint(receipt_ctx({ reason = "ENFORCE_DECIDE_UNAVAILABLE" }))
eq(unsafe.authoritative_decision, "not_safely_decided",
  "the three-valued outcome is never collapsed to deny")

-- Rule R5: authorized but NOT executed is a legitimate, recordable state.
local unforwardable = receipt.mint(receipt_ctx({ reason = "ENFORCE_FORWARD_ONCE_UNAVAILABLE" }))
eq(unforwardable.authoritative_decision, "allow",
  "R5: the decision allowed and the boundary declined to execute")
eq(unforwardable.forwarded_count, 0, "R5: an allow that was not forwarded counts zero")

-- Deny-closed about its own inputs. A fallback outcome is exactly the shape of
-- a refusal that reads as a pass, so an unknown reason mints nothing.
local bad, bad_err = receipt.mint(receipt_ctx({ reason = "ENFORCE_SOMETHING_NEW" }))
check(bad == nil, "an unknown reason code is refused, never defaulted")
check(bad_err ~= nil and bad_err:find("unknown boundary outcome reason", 1, true) ~= nil,
  "the refusal names the unknown reason", bad_err)

local no_id = receipt.mint(receipt_ctx({ receipt_id = "" }))
check(no_id == nil, "a receipt with no identity is refused")
local no_clock = receipt.mint(receipt_ctx({ observed_at = "" }))
check(no_clock == nil, "a receipt with no boundary clock is refused")
check(receipt.mint("not a table") == nil, "a non-table context is refused")

-- A refusal that fires with no bundle at all has no bundle-bound fact to
-- state, and states none. The merged proposal marks all of them NOT NULL.
local no_bundle = receipt.mint({
  receipt_id = "rcpt-nb", observed_at = "2026-07-27T00:00:00Z",
  reason = "ENFORCE_NO_VALID_BUNDLE",
  adapter_type = "kong_mudraid_enforce", adapter_version = "0.1.0",
})
eq(no_bundle.bundle_version, 0, "no bundle means no bundle version to state")
eq(no_bundle.bundle_digest, "", "no bundle means no bundle digest to state")
eq(no_bundle.environment, "", "environment comes from the signed bundle surface")
eq(no_bundle.boundary_outcome, "failed_closed", "no valid bundle fails closed")

eq(receipt.SCHEMA_VERSION, "1.0.0", "receipt schema version pinned")

-- ---------------------------------------------------------------------------
-- Signed containment projection (doc 05 A05-06/A05-07)
-- ---------------------------------------------------------------------------

local containment = require "kong.plugins.mudraid-enforce.containment"

-- CROSS-LANGUAGE VECTOR. These are the EXACT bytes
-- ContainmentFeedRecord.canonical_bytes() produces in
-- services/enforcement-service/app/domain/containment/feed/record.py, and the
-- exact digest FeedKeyring.sign() produces over them under
-- CONTAINMENT_FEED_SECRET below. test_mudraid_enforce_contract.py recomputes
-- both by importing that server module, so a change to either side's
-- serialization fails the build instead of failing signature verification in
-- staging. Change them only in BOTH places.
local CONTAINMENT_CANONICAL_VECTOR =
  'org_1\000staging\000snapshot\0007\0002026-08-09T12:00:00+00:00\031platform\00011111111-1111-1111-1111-111111111111\000tenant\000block\0003\000target_quarantined\0002026-08-09T11:00:00+00:00\031action\000payments.send\000tenant\000block\0001\000target_quarantined\0002026-08-09T11:30:00+00:00'

local CONTAINMENT_CANONICAL_EMPTY =
  'org_1\000staging\000snapshot\0001\0002026-08-09T12:00:00+00:00\031'

-- Real HMAC-SHA256 over the two vectors above; asserted in the optional
-- real-crypto section and independently recomputed in Python.
local CONTAINMENT_FEED_SECRET = "test-containment-secret"
local CONTAINMENT_VECTOR_DIGEST =
  "22a48a84714b81e156857b550ea99f2a534d2c508d7620ba07f4ebdf331ffe09"
local CONTAINMENT_ACK_SECRET = "test-ack-secret"
local CONTAINMENT_ACK_CANONICAL =
  'org_1\000staging\000kong-staging-1\0007\0002026-08-09T12:00:05+00:00'
local CONTAINMENT_ACK_DIGEST =
  "3b471a813254c268f28f7b81501424ff7b3d9122038c9d7ee1d8007c3d8688e3"

eq(string.byte(containment.FIELD_SEP), 0, "containment field separator is NUL (record.py)")
eq(string.byte(containment.ENTRY_SEP), 31, "containment entry separator is US (record.py)")

local function centry(over)
  local e = {
    target_type = "platform",
    target_id = "11111111-1111-1111-1111-111111111111",
    scope = "tenant",
    op = "block",
    state_epoch = 3,
    reason_code = "target_quarantined",
    effective_at = "2026-08-09T11:00:00+00:00",
  }
  for k, v in pairs(over or {}) do e[k] = v end
  return e
end

local function crecord(over)
  local r = {
    organization_id = "org_1",
    environment = "staging",
    kind = "snapshot",
    sequence = 1,
    issued_at = "2026-08-09T12:00:00+00:00",
    entries = {},
  }
  for k, v in pairs(over or {}) do r[k] = v end
  return r
end

-- The vector record, byte-for-byte.
local vector_record = crecord({
  sequence = 7,
  entries = {
    centry(),
    centry({ target_type = "action", target_id = "payments.send", state_epoch = 1,
             effective_at = "2026-08-09T11:30:00+00:00" }),
  },
})
eq(containment.canonical_bytes(vector_record), CONTAINMENT_CANONICAL_VECTOR,
  "containment canonical bytes match the server's ContainmentFeedRecord")
eq(containment.canonical_bytes(crecord()), CONTAINMENT_CANONICAL_EMPTY,
  "an EMPTY snapshot still emits the trailing entry separator")

-- Instants. Freshness is a security bound, so anything that cannot be placed
-- on a timeline is refused rather than guessed at.
eq(containment.parse_instant("2026-08-09T12:00:00+00:00"), 1786276800,
  "parse_instant reads the Python isoformat spelling")
eq(containment.parse_instant("2026-08-09T12:00:00Z"), 1786276800,
  "parse_instant reads the Z spelling")
eq(containment.parse_instant("2026-08-09T12:00:00.123456+00:00"), 1786276800,
  "fractional seconds are tolerated at whole-second resolution")
eq(containment.parse_instant("2026-08-09T17:30:00+00:00"), 1786296600,
  "parse_instant is arithmetic, not a table lookup")
eq(containment.parse_instant("2026-08-09T12:00:00+05:30"), 1786276800 - 19800,
  "a non-UTC offset is applied, not ignored")
eq(containment.parse_instant("1970-01-01T00:00:00Z"), 0, "epoch zero")
check(containment.parse_instant("2026-08-09T12:00:00") == nil,
  "a NAIVE instant is refused rather than assumed UTC")
check(containment.parse_instant("yesterday") == nil, "garbage is refused")
check(containment.parse_instant(nil) == nil, "a missing instant is refused")
check(containment.parse_instant("2026-13-09T12:00:00Z") == nil, "month 13 is refused")

-- Verification. Logic is exercised with the injected fake crypto (the real
-- algorithm vectors run in the optional section below), exactly as bundle.lua's
-- tests do.
local function csign(r, secret)
  r.signature = {
    key_id = "containment-feed-v1",
    algorithm = "HMAC-SHA256",
    digest = fake_crypto.hmac_sha256_hex(secret or CONTAINMENT_FEED_SECRET,
      containment.canonical_bytes(r)),
  }
  return r
end

local copts = { crypto = fake_crypto, secret = CONTAINMENT_FEED_SECRET }

local cv = containment.verify(csign(crecord({ entries = { centry() } })), copts)
check(cv ~= nil, "a correctly signed snapshot verifies")
eq(cv and cv.sequence, 1, "verification carries the sequence forward")
eq(cv and cv.issued_at_epoch, 1786276800, "verification places the issue instant")

-- One distinct typed refusal per distinguishable cause (bundle.verify's rule).
local function crefusal(record, opts)
  local _, code = containment.verify(record, opts or copts)
  return code
end

eq(crefusal("not a table"), "CONTAINMENT_RESPONSE_INVALID", "a non-object response is refused")
eq(crefusal(csign(crecord({ kind = "digest" }))), "CONTAINMENT_KIND_UNSUPPORTED",
  "an unknown record kind is refused, never best-effort parsed")
eq(crefusal(csign(crecord({ sequence = 0 }))), "CONTAINMENT_RESPONSE_INVALID",
  "sequence is 1-based and monotonic")
eq(crefusal(csign(crecord({ issued_at = "whenever" }))), "CONTAINMENT_TIMESTAMP_INVALID",
  "an unplaceable issue instant is its own refusal (no instant, no freshness bound)")
eq(crefusal(csign(crecord({ entries = { centry({ op = "maybe" }) } }))),
  "CONTAINMENT_ENTRY_INVALID", "an entry that is neither block nor lift is refused")
eq(crefusal(csign(crecord({ entries = { centry({ target_id = "" }) } }))),
  "CONTAINMENT_ENTRY_INVALID", "an entry with an unbound target is refused")
eq(crefusal(csign(crecord({ entries = { centry({ state_epoch = 0 }) } }))),
  "CONTAINMENT_ENTRY_INVALID", "an entry epoch the state master cannot have produced is refused")

-- The two refusals that never clear on their own, and are therefore never
-- reported as an ordinary signature failure.
eq(crefusal(csign(crecord()), { crypto = fake_crypto, secret = "" }),
  "CONTAINMENT_SIGNING_SECRET_UNCONFIGURED",
  "no signing secret is a MISCONFIGURATION, not a verification failure")
eq(crefusal(csign(crecord()),
    { crypto = fake_crypto, secret = CONTAINMENT_FEED_SECRET, key_id = "containment-feed-v2" }),
  "CONTAINMENT_SIGNING_KEY_UNKNOWN",
  "a record under a key this adapter was never given is its own refusal")

local wrong_alg = csign(crecord())
wrong_alg.signature.algorithm = "HMAC-SHA1"
eq(crefusal(wrong_alg), "CONTAINMENT_SIGNATURE_ALGORITHM_UNSUPPORTED",
  "an unknown algorithm is refused, never verified with the one we have")

eq(crefusal(csign(crecord(), "the-wrong-secret")), "CONTAINMENT_SIGNATURE_INVALID",
  "an HMAC that does not verify is refused")

local tampered = csign(crecord({ entries = { centry() } }))
tampered.entries[1].target_id = "22222222-2222-2222-2222-222222222222"
eq(crefusal(tampered), "CONTAINMENT_SIGNATURE_INVALID",
  "retargeting a signed entry breaks the signature")

local unsigned = crecord()
unsigned.signature = nil
eq(crefusal(unsigned), "CONTAINMENT_RESPONSE_INVALID", "an UNSIGNED record is never trusted")

-- Ordering rules against what is already applied.
local base = containment.apply(nil,
  containment.verify(csign(crecord({ sequence = 5, entries = { centry() } })), copts))
check(base ~= nil, "a verified snapshot applies")
eq(base.sequence, 5, "the applied projection carries the sequence")
eq(base.block_count, 1, "the applied projection carries the blocks")

local with_active = { crypto = fake_crypto, secret = CONTAINMENT_FEED_SECRET, active = base }
eq(crefusal(csign(crecord({ sequence = 4 })), with_active), "CONTAINMENT_SEQUENCE_REGRESSION",
  "an older sequence never replaces a newer applied projection")
local same_seq_other_bytes = csign(crecord({ sequence = 5, entries = {} }))
eq(crefusal(same_seq_other_bytes, with_active), "CONTAINMENT_SEQUENCE_CONFLICT",
  "the same sequence with different bytes is a conflict, not an update")
eq(crefusal(csign(crecord({ sequence = 7, kind = "delta" })), with_active),
  "CONTAINMENT_DELTA_GAP", "a delta over a gap is refused, never applied")
eq(crefusal(csign(crecord({ sequence = 1, kind = "delta" })), copts),
  "CONTAINMENT_DELTA_GAP", "a delta cannot establish a projection with no baseline")
eq(crefusal(csign(crecord({ sequence = 6, environment = "production" })), with_active),
  "CONTAINMENT_STREAM_MISMATCH",
  "a record from another tenant/environment stream never folds into this one")

local resent = containment.verify(csign(crecord({ sequence = 5, entries = { centry() } })),
  with_active)
check(resent ~= nil and resent.no_change, "the same sequence with the same bytes is a no-op")

-- Application is atomic: apply() builds a WHOLE new projection and never
-- touches the live one, which is what makes the handler's single-assignment
-- swap safe for an in-flight request.
local delta = containment.verify(csign(crecord({
  sequence = 6, kind = "delta",
  entries = {
    centry({ op = "lift" }),
    centry({ target_type = "action", target_id = "payments.send", state_epoch = 4,
             effective_at = "2026-08-09T12:30:00+00:00" }),
  },
})), with_active)
check(delta ~= nil, "a delta exactly one past the applied sequence verifies")
local next_projection = containment.apply(base, delta)
eq(next_projection.sequence, 6, "the delta advances the sequence")
eq(next_projection.block_count, 1, "the delta lifted one block and added another")
eq(base.block_count, 1, "apply() never mutated the live projection")
check(base.blocks[containment.identity_key(
  "platform", "11111111-1111-1111-1111-111111111111", "tenant")] ~= nil,
  "the previous projection still holds its own block after a newer one is built")

-- The check that runs before any allow.
local PLATFORM = "11111111-1111-1111-1111-111111111111"
local function subject(over)
  local s = {
    { target_type = "platform", target_id = PLATFORM },
    { target_type = "resource", target_id = "https://mcp.example.com/mcp" },
    { target_type = "action", target_id = "email.send" },
  }
  for k, v in pairs(over or {}) do s[k] = v end
  return s
end
local FRESH = { now = 1786276800 + 10, max_staleness_seconds = 300 }

eq(select(1, containment.evaluate(nil, subject(), FRESH)), containment.UNAVAILABLE,
  "no projection is UNAVAILABLE — never read as 'nothing is contained'")

local clear_projection = containment.apply(nil,
  containment.verify(csign(crecord({ entries = {} })), copts))
eq(select(1, containment.evaluate(clear_projection, subject(), FRESH)), containment.CLEAR,
  "a fresh projection with no matching block is clear")

local blocked_status, blocked_why =
  containment.evaluate(base, subject(), { now = 1786276800 + 10, max_staleness_seconds = 300 })
eq(blocked_status, containment.BLOCKED, "a blocked platform stops the action before any allow")
eq(blocked_why.reason_code, "target_quarantined", "the block carries the governed reason code")
eq(blocked_why.sequence, 5, "the block names the projection sequence it came from")

-- Scope is a qualifier on APPLY and not a filter on LOOKUP: a block entered at
-- any scope stops the request (wrong direction is stricter).
local other_scope = containment.apply(nil, containment.verify(
  csign(crecord({ entries = { centry({ scope = "organization" }) } })), copts))
eq(select(1, containment.evaluate(other_scope, subject(), FRESH)), containment.BLOCKED,
  "a block at a different scope still stops the request")

-- ...but a lift at one scope never clears a block at another.
local two_scopes = containment.apply(nil, containment.verify(csign(crecord({
  entries = { centry(), centry({ scope = "organization" }) },
})), copts))
eq(two_scopes.block_count, 2, "two scopes of one target are two distinct blocks")
local lifted_one = containment.apply(two_scopes, containment.verify(csign(crecord({
  sequence = 2, kind = "delta", entries = { centry({ op = "lift" }) },
})), { crypto = fake_crypto, secret = CONTAINMENT_FEED_SECRET, active = two_scopes }))
eq(lifted_one.block_count, 1, "a lift clears exactly its own scope")
eq(select(1, containment.evaluate(lifted_one, subject(), FRESH)), containment.BLOCKED,
  "the surviving block at another scope still stops the request")

-- Action- and resource-scoped blocks bind from verified material.
local action_blocked = containment.apply(nil, containment.verify(csign(crecord({
  entries = { centry({ target_type = "action", target_id = "email.send" }) },
})), copts))
eq(select(1, containment.evaluate(action_blocked, subject(), FRESH)), containment.BLOCKED,
  "a contained canonical action is blocked")
local resource_blocked = containment.apply(nil, containment.verify(csign(crecord({
  entries = { centry({ target_type = "resource", target_id = "https://mcp.example.com/mcp" }) },
})), copts))
eq(select(1, containment.evaluate(resource_blocked, subject(), FRESH)), containment.BLOCKED,
  "a contained canonical resource is blocked")

-- Target types this adapter cannot bind pre-/decide are COUNTED, not silently
-- dropped, and do not block a request they cannot be matched against.
local agent_scoped = containment.apply(nil, containment.verify(csign(crecord({
  entries = { centry({ target_type = "agent", target_id = "agent-9" }) },
})), copts))
eq(agent_scoped.unevaluable, 1, "a target type the adapter cannot bind is measured")
eq(select(1, containment.evaluate(agent_scoped, subject(), FRESH)), containment.CLEAR,
  "it does not block here — the authoritative live path is what covers it")

-- Freshness. A disconnected adapter may use its last projection only within
-- its configured maximum staleness (A05-06).
eq(select(1, containment.evaluate(clear_projection, subject(),
    { now = 1786276800 + 301, max_staleness_seconds = 300 })), containment.STALE,
  "past the maximum staleness the action denies rather than continuing")
eq(select(1, containment.evaluate(clear_projection, subject(),
    { now = 1786276800 + 300, max_staleness_seconds = 300 })), containment.CLEAR,
  "exactly at the bound is still inside it")
eq(select(1, containment.evaluate(clear_projection, subject(),
    { now = 1786276800 - 3600, max_staleness_seconds = 300 })), containment.STALE,
  "a projection issued far in OUR future has no usable freshness bound")
eq(select(1, containment.evaluate(clear_projection, subject(),
    { now = 1786276800 - 10, max_staleness_seconds = 300 })), containment.CLEAR,
  "ordinary clock skew is tolerated")

-- A BLOCK is reported even on a projection past its freshness bound: staleness
-- makes the projection's SILENCE untrustworthy, not its blocks. Over-blocking
-- is the safe direction; under-blocking is not.
eq(select(1, containment.evaluate(base, subject(),
    { now = 1786276800 + 100000, max_staleness_seconds = 300 })), containment.BLOCKED,
  "a stale projection's block is still a block")

-- Acknowledgement (A05-06 item 3).
local ack_projection = containment.apply(nil,
  containment.verify(csign(crecord({ sequence = 7 })), copts))
local ack, ack_code = containment.acknowledgement(ack_projection, {
  crypto = fake_crypto,
  adapter_id = "kong-staging-1",
  secret = CONTAINMENT_ACK_SECRET,
  key_id = "containment-ack-v1",
  acknowledged_at = "2026-08-09T12:00:05+00:00",
})
check(ack ~= nil, "an applied projection is acknowledgeable", ack_code)
eq(ack and ack.acknowledged_sequence, 7, "the acknowledgement names the ACTIVE sequence")
eq(ack and ack.signature.algorithm, "HMAC-SHA256", "the acknowledgement is HMAC-signed")
eq(ack and ack.signature.digest,
  fake_crypto.hmac_sha256_hex(CONTAINMENT_ACK_SECRET, CONTAINMENT_ACK_CANONICAL),
  "the acknowledgement signs the server's SignedAdapterAcknowledgement bytes")

eq(select(2, containment.acknowledgement(ack_projection, {
    crypto = fake_crypto, secret = CONTAINMENT_ACK_SECRET,
    acknowledged_at = "2026-08-09T12:00:05+00:00" })),
  "CONTAINMENT_ACK_ADAPTER_ID_UNCONFIGURED",
  "an unattributed acknowledgement cannot count toward a convergence claim")
eq(select(2, containment.acknowledgement(ack_projection, {
    crypto = fake_crypto, adapter_id = "kong-staging-1", secret = "",
    acknowledged_at = "2026-08-09T12:00:05+00:00" })),
  "CONTAINMENT_ACK_SECRET_UNCONFIGURED",
  "an UNSIGNED acknowledgement is refused rather than sent")
eq(select(2, containment.acknowledgement(nil, { crypto = fake_crypto })),
  "CONTAINMENT_ACK_NOTHING_APPLIED",
  "there is nothing to acknowledge without an applied projection")

-- The "+00:00" spelling is load-bearing: the server re-serializes the instant
-- with datetime.isoformat() before recomputing the digest, and a trailing "Z"
-- would not be the bytes we signed.
check(containment.iso_utc_offset(1786276805) == "2026-08-09T12:00:05+00:00",
  "iso_utc_offset emits the spelling the server's canonical bytes use",
  containment.iso_utc_offset(1786276805))

-- ---------------------------------------------------------------------------
-- OPTIONAL: real crypto vectors (runs inside the kong image where the
-- resty/OpenSSL bindings are importable; skipped cleanly elsewhere).
-- Expected values are recomputed independently by the Python contract test.
-- ---------------------------------------------------------------------------

local ok_crypto, real_crypto = pcall(require, "kong.plugins.mudraid-enforce.crypto")
if ok_crypto then
  local ok_run, run_err = pcall(function()
    eq(real_crypto.sha256_hex("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "real sha256 vector")
    eq(real_crypto.hmac_sha256_hex("key", "The quick brown fox jumps over the lazy dog"),
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
      "real hmac-sha256 vector")
    -- The containment vectors under the REAL algorithm: these are the digests
    -- enforcement-service's FeedKeyring.sign() produces, so a passing assertion
    -- here means a record this gateway fetches in staging verifies for the
    -- right reason rather than by agreement between two fakes.
    eq(real_crypto.hmac_sha256_hex(CONTAINMENT_FEED_SECRET, CONTAINMENT_CANONICAL_VECTOR),
      CONTAINMENT_VECTOR_DIGEST, "real containment feed signature vector")
    eq(real_crypto.hmac_sha256_hex(CONTAINMENT_ACK_SECRET, CONTAINMENT_ACK_CANONICAL),
      CONTAINMENT_ACK_DIGEST, "real containment acknowledgement signature vector")
  end)
  if not ok_run then
    failures = failures + 1
    print("FAIL real-crypto vectors errored: " .. tostring(run_err))
  end
else
  print("skip real-crypto vectors (resty/OpenSSL bindings unavailable outside the gateway image)")
end

-- ---------------------------------------------------------------------------
-- MULTI-TENANT (Option B) — cross-tenant negative tests
--
-- Step 1 of the delivery order in
-- docs/5 features/outputs 2/m0/DESIGN-2026-08-01-multi-tenant-enforcement.md.
-- These exist BEFORE the implementation deliberately: the design record marks
-- them the load-bearing control, because Option B is being built without live
-- multi-tenant traffic to catch what the tests miss.
--
-- WHY THIS IS THE RIGHT PLACE TO PUT THE PRESSURE
--
-- handler.lua forwards the /decide surface binding STRAIGHT FROM THE BUNDLE:
--
--     local surface = b.payload.content.surface
--     surface = { platform_id = ..., environment = ..., canonical_resource_uri = ... }
--
-- with the comment "These come only from the signed bundle content, never from
-- client headers." Today that is exactly right — there is one bundle and it is
-- necessarily this tenant's.
--
-- Under Option B it inverts: WHICHEVER BUNDLE SELECTION PICKS DEFINES THE
-- TENANT IDENTITY OF THE REQUEST. Pick wrong and /decide receives a validly
-- signed, non-empty surface for the wrong tenant, and enforcement-service
-- returns a CORRECT decision about the WRONG tenant's resource. Nothing
-- downstream can detect that, because every field it checks is authentic.
--
-- So the dangerous case is not "no bundle found". It is "wrong bundle found,
-- and everything after it trusts the answer."
-- ---------------------------------------------------------------------------

local tenants = require "kong.plugins.mudraid-enforce.tenants"

-- (a) The one invariant worth restating here.
--
--     Surface-binding refusals are ALREADY covered above ("AUDIT-006 M4 —
--     surface binding contract"): absent, JSON-null, empty and blank
--     canonical_resource_uri, absent environment and platform_id, and a
--     missing surface entirely, each asserting BUNDLE_SURFACE_UNBOUND. Those
--     tests are the baseline; re-asserting them here would be duplication that
--     reads as extra safety and provides none.
--
--     What is NOT covered anywhere is the fact below, and it is the one that
--     makes multi-tenant hard.

do
  -- ONE SHARED HMAC SIGNS EVERY TENANT.
  --
  -- A bundle carrying a DIFFERENT tenant's surface, signed with the same
  -- platform secret, verifies exactly as well as this tenant's. That is
  -- correct today -- there is one bundle and it is necessarily ours -- and it
  -- is the precise reason step 4 of the delivery order exists.
  --
  -- A valid signature proves THE PLATFORM signed it. It does not prove it
  -- belongs to the requesting tenant. Under Option B, where selection decides
  -- which bundle answers a request, signature validity therefore carries none
  -- of the weight it appears to: the wrong bundle is just as authentic as the
  -- right one, and handler.lua forwards its surface to /decide verbatim.
  local other = make_payload(3)
  other.content.surface.platform_id = "some-other-tenant"
  other.content.surface.canonical_resource_uri = "https://other.example/mcp"
  local got = select(1, verify(make_fetched(other, SECRET)))
  check(got ~= nil,
    "multitenant: another tenant's surface verifies under the shared HMAC",
    "if this ever FAILS, signature-level tenant binding was added and step 4 of "
    .. "the delivery order should be revisited before relying on it")
end

-- (b) The Option B contract, IMPLEMENTED (step 3). These were recorded as
--     PENDING specs in step 1, before any selection code existed, precisely so
--     that the implementation would be measured against a specification it did
--     not get to write. Each is now a real assertion against tenants.lua; none
--     was deleted or weakened to make the implementation pass.
--
--     Every one asserts a DENIAL or a REFUSAL. There is no positive
--     multi-tenant case here on purpose: this file is the control, and a
--     control that also certifies success can be satisfied by code that always
--     says yes. (The positive path is exercised by the gateway's own build
--     gate 2, which boots Kong against the rendered config.)
--
--     Selection lives in tenants.lua rather than handler.lua so it can be
--     executed here at all: the handler needs kong/ngx/resty.http and only
--     runs inside a gateway, and a control asserted about unexecutable code is
--     not a control.

local TENANT_A = "11111111-1111-1111-1111-111111111111"
local TENANT_B = "22222222-2222-2222-2222-222222222222"

local function conf_for(id) return { surface_platform_id = id } end

-- A set built the way the handler builds one: plan from all instances, then
-- load bundles into the slots that polled successfully.
local function set_with(confs, loaded)
  local set = tenants.new()
  set.plan = tenants.plan(confs)
  for key, b in pairs(loaded or {}) do
    tenants.slot(set, key).bundle = b
  end
  return set
end

do -- (b1) a request matching NO bundle's surface is denied
  -- Tenant A is configured and has NOT loaded a bundle; tenant B has. The
  -- dangerous behaviour is A's request being answered from the one bundle
  -- that happens to be present.
  local set = set_with({ conf_for(TENANT_A), conf_for(TENANT_B) },
    { [TENANT_B] = { bundle_version = 7 } })
  local b, reason = tenants.select(set, conf_for(TENANT_A))
  check(b == nil, "multitenant: a surface with no bundle is denied, never filled in",
    "selection returned a bundle for a surface that has none")
  eq(reason, tenants.NO_BUNDLE, "multitenant: the denial reason is no_valid_bundle")
end

do -- (b2) tenant A's route never resolves tenant B's bundle
  -- Both loaded. This is the core isolation property: the answer depends on
  -- the asking instance's declared surface and on nothing else — not on which
  -- bundle polled most recently, which is the shape a naive port takes.
  local set = set_with({ conf_for(TENANT_A), conf_for(TENANT_B) }, {
    [TENANT_A] = { bundle_version = 1, tag = "A" },
    [TENANT_B] = { bundle_version = 2, tag = "B" },
  })
  local got_a = tenants.select(set, conf_for(TENANT_A))
  local got_b = tenants.select(set, conf_for(TENANT_B))
  eq(got_a and got_a.tag, "A", "multitenant: tenant A resolves tenant A's bundle")
  eq(got_b and got_b.tag, "B", "multitenant: tenant B resolves tenant B's bundle")
  check(got_a ~= got_b, "multitenant: two tenants never resolve the same bundle object",
    "both routes resolved one shared bundle — the single-tenant defect")
end

do -- (b3) two instances claiming one surface is a REFUSAL, not a tie to break
  local set = set_with({ conf_for(TENANT_A), conf_for(TENANT_A) },
    { [TENANT_A] = { bundle_version = 1 } })
  local b, reason = tenants.select(set, conf_for(TENANT_A))
  check(b == nil, "multitenant: an ambiguous surface refuses rather than choosing",
    "selection picked a winner between two instances claiming one surface")
  eq(reason, tenants.AMBIGUOUS, "multitenant: the refusal reason is surface_ambiguous")
end

do -- (b4) the selected bundle is the one bound to the asking instance
  -- handler.lua forwards `b.payload.content.surface` to /decide verbatim, so
  -- "which bundle was selected" IS the tenant identity of the decision. This
  -- asserts the binding at the point where it is decided.
  local set = set_with({ conf_for(TENANT_A), conf_for(TENANT_B) }, {
    [TENANT_A] = { payload = { content = { surface = { platform_id = TENANT_A } } } },
    [TENANT_B] = { payload = { content = { surface = { platform_id = TENANT_B } } } },
  })
  local got = tenants.select(set, conf_for(TENANT_B))
  eq(got and got.payload.content.surface.platform_id, TENANT_B,
    "multitenant: the /decide surface is the SELECTED bundle's, not a neighbour's")
end

do -- (b5) a valid signature does not imply tenant ownership
  -- The executable half of this is asserted above: another tenant's surface
  -- verifies perfectly under the shared HMAC. What step 3 adds is the check
  -- that catches it, and it is an IDENTITY check, not a cryptographic one --
  -- three independent statements of who this surface belongs to must agree.
  eq(tenants.attribution_conflict(TENANT_A, TENANT_A, TENANT_A), nil,
    "multitenant: declared, attributed and claimed agreeing is consistent")
  eq(tenants.attribution_conflict(TENANT_A, TENANT_B, TENANT_B),
    "declared_surface_mismatch",
    "multitenant: a credential attributed to another tenant is refused")
  eq(tenants.attribution_conflict(TENANT_A, TENANT_A, TENANT_B),
    "payload_surface_mismatch",
    "multitenant: a validly signed bundle claiming another tenant is refused")
  eq(tenants.attribution_conflict(TENANT_A, nil, nil), "surface_unattributed",
    "multitenant: a declared surface with nothing binding a bundle to it is refused")
  -- The undeclared compatibility slot has no declared surface to check, but
  -- the two REMOTE statements must still agree with each other.
  eq(tenants.attribution_conflict(tenants.UNBOUND_KEY, TENANT_A, TENANT_B),
    "payload_surface_mismatch",
    "multitenant: an undeclared slot still refuses when server and payload disagree")
  eq(tenants.attribution_conflict(tenants.UNBOUND_KEY, TENANT_A, TENANT_A), nil,
    "multitenant: an undeclared slot with agreeing remote statements is consistent")
end

do -- (b6) header stripping uses the SELECTED bundle
  -- handler.lua calls strip_reserved_headers(b) with the result of
  -- tenants.select, and the strip now runs AFTER selection for exactly this
  -- reason. The property that makes that correct is asserted here: the object
  -- handed to the strip is the asking tenant's, so a tenant's strip_prefixes
  -- can never come from a neighbour's bundle.
  local set = set_with({ conf_for(TENANT_A), conf_for(TENANT_B) }, {
    [TENANT_A] = { strip_prefixes = { "x-a-" } },
    [TENANT_B] = { strip_prefixes = { "x-b-" } },
  })
  local got = tenants.select(set, conf_for(TENANT_A))
  eq(got and got.strip_prefixes[1], "x-a-",
    "multitenant: the strip list comes from the selected tenant's bundle")
  -- And when selection refuses, there is no bundle to strip against at all —
  -- headers_mod falls back to its built-in prefixes rather than a neighbour's.
  local none = tenants.select(set_with({ conf_for(TENANT_A) }, {}), conf_for(TENANT_A))
  eq(none, nil, "multitenant: a refused selection yields no bundle to strip against")
end

do -- (b7) a bundle set with zero entries denies exactly as nil does
  local empty = tenants.new()
  local b, reason = tenants.select(empty, conf_for(TENANT_A))
  check(b == nil, "multitenant: an empty set denies",
    "an empty set read as 'nothing to enforce'")
  eq(reason, tenants.UNIDENTIFIED,
    "multitenant: an unplanned surface is unidentified, not merely unloaded")
end

do -- The compatibility slot, and the moment it stops being safe.
  -- A single undeclared instance is today's staging gateway and must keep
  -- working; a second instance makes "the obvious one" stop existing, so the
  -- undeclared slot refuses from that moment rather than an operator having to
  -- remember to close it.
  local alone = set_with({ {} }, { [tenants.UNBOUND_KEY] = { bundle_version = 4 } })
  local got = tenants.select(alone, {})
  eq(got and got.bundle_version, 4,
    "multitenant: a lone undeclared instance keeps resolving (compatibility)")

  local crowded = set_with({ {}, conf_for(TENANT_A) },
    { [tenants.UNBOUND_KEY] = { bundle_version = 4 } })
  local b2, reason2 = tenants.select(crowded, {})
  check(b2 == nil, "multitenant: an undeclared instance refuses once it is not alone",
    "the compatibility slot stayed open after a second instance appeared")
  eq(reason2, tenants.UNIDENTIFIED,
    "multitenant: the refusal reason is surface_unidentified")
  -- ...and the declared neighbour is unaffected by that refusal. Partial
  -- failure is per tenant, never global.
  eq(select(2, tenants.select(crowded, conf_for(TENANT_A))), tenants.NO_BUNDLE,
    "multitenant: one surface's refusal does not change another surface's outcome")
end

-- ---------------------------------------------------------------------------
-- HARDENING: constant-time tag comparison
-- ---------------------------------------------------------------------------
--
-- compare.lua replaces `~=` on the two HMAC comparisons. These lock the
-- FUNCTIONAL contract; the timing property itself is not measurable from a
-- deterministic unit test and is not claimed here (see compare.lua's header for
-- the honest scope).

do
  local compare = require "kong.plugins.mudraid-enforce.compare"

  check(compare.equals("", ""), "constant-time: empty equals empty")
  check(compare.equals("abc", "abc"), "constant-time: equal strings compare equal")
  check(not compare.equals("abc", "abd"), "constant-time: a last-byte difference is caught")
  check(not compare.equals("abc", "bbc"), "constant-time: a first-byte difference is caught")
  check(not compare.equals("abc", "abcd"), "constant-time: a length difference is caught")
  check(not compare.equals("abcd", "abc"), "constant-time: length asymmetry is caught")
  check(not compare.equals(nil, "abc"), "constant-time: a nil operand is never equal")
  check(not compare.equals("abc", nil), "constant-time: a nil operand is never equal (rhs)")
  check(not compare.equals(123, 123), "constant-time: non-strings are never equal")
  -- High bytes must compare by value, not by anything locale-ish.
  check(compare.equals(string.char(0, 255, 128), string.char(0, 255, 128)),
    "constant-time: NUL and high bytes compare by value")
  check(not compare.equals(string.char(0, 255), string.char(0, 254)),
    "constant-time: a high-byte difference is caught")
end

-- ---------------------------------------------------------------------------
-- HARDENING: protected-path normalization (the surface-test bypass)
-- ---------------------------------------------------------------------------
--
-- `kong.request.get_path()` returns the RAW path while Kong's router matched a
-- normalized one, so an encoded or dot-segmented spelling of a protected path
-- used to miss the prefix test — and missing it does not deny, it SKIPS the
-- whole control loop and forwards.

do
  local path = require "kong.plugins.mudraid-enforce.path"

  eq(path.percent_decode("/%6dcp/messages"), "/mcp/messages",
    "path: a percent-escape is decoded")
  eq(path.percent_decode("/mcp%2fmessages"), "/mcp/messages",
    "path: an encoded slash is decoded")
  eq(path.percent_decode("/mcp"), "/mcp", "path: a plain path is unchanged")
  eq(path.percent_decode("/100%"), "/100%", "path: a stray percent is left verbatim")
  eq(path.percent_decode("/a%zz"), "/a%zz", "path: a malformed escape is left verbatim")
  -- RFC 3986 §2.4: decode once. %25 is "%", so %252f becomes the TEXT "%2f"
  -- and stops there rather than becoming a slash.
  eq(path.percent_decode("/mcp%252fx"), "/mcp%2fx",
    "path: decoding happens exactly once, never repeatedly")

  eq(path.remove_dot_segments("/mcp/./messages"), "/mcp/messages",
    "path: a single-dot segment is removed")
  eq(path.remove_dot_segments("/a/b/../c"), "/a/c", "path: a double-dot segment pops")
  eq(path.remove_dot_segments("/../mcp"), "/mcp",
    "path: a leading double-dot cannot escape the root")
  eq(path.remove_dot_segments("/mcp"), "/mcp", "path: a normal path is unchanged")

  eq(path.normalize("/%6dcp/../%6dcp/messages"), "/mcp/messages",
    "path: decode then resolve, in that order")

  -- The union property: the raw spelling is ALWAYS a candidate, so
  -- normalization can only widen the protected set.
  local function has(list, want)
    for i = 1, #list do
      if list[i] == want then return true end
    end
    return false
  end
  local c = path.candidates("/%6dcp/messages")
  check(has(c, "/%6dcp/messages"), "path: the raw spelling is always a candidate")
  check(has(c, "/mcp/messages"), "path: the decoded spelling is a candidate")
  eq(#path.candidates("/mcp"), 1,
    "path: an already-normal path costs exactly one candidate")
  eq(#path.candidates(""), 0, "path: an empty path yields nothing to test")

  -- THE HANDLER'S ACTUAL PREDICATE, not a copy of it. handler.lua binds
  -- `is_protected = path.is_protected`, so these assertions exercise the
  -- function the gateway calls; a copy here would only prove the copy right.
  local is_protected = path.is_protected

  local PROTECTED = { "/mcp" }
  check(is_protected(PROTECTED, "/mcp/messages"), "surface: the plain path is protected")
  check(is_protected(PROTECTED, "/%6dcp/messages"),
    "surface: a percent-encoded path is protected (was a total bypass)")
  check(is_protected(PROTECTED, "/mcp/../mcp/messages"),
    "surface: a dot-segmented path is protected (was a total bypass)")
  check(is_protected(PROTECTED, "/%6D%63%70/messages"),
    "surface: a fully-encoded path is protected, and decoding is case-insensitive on hex")
  check(not is_protected(PROTECTED, "/public/health"),
    "surface: an unrelated path is still not protected")
  check(not is_protected(PROTECTED, "/x%252fmcp"),
    "surface: decode-once means %252f does not invent a protected match")
end

-- ---------------------------------------------------------------------------
-- HARDENING: the segment-boundary rule (AUDIT-008 P1-3)
-- ---------------------------------------------------------------------------
--
-- The old test was a LEXICAL prefix, which does not know a path is made of
-- segments: a configured `/mcp` also claimed `/mcpfoo` and `/mcp-evil`. That
-- direction is fail-closed, so it was never an authority bypass — it is a
-- disagreement between the implementation and the single-segment surface the
-- deployment declares, and it surfaces as an unrelated neighbouring route
-- answering 405/400 because the MCP control loop was applied to it.
--
-- The case table is AUDIT-008 P1-3's own, and the SAME table is asserted against
-- the Python middleware in test_hardening.py::test_the_two_adapters_agree_...
-- so the two adapters cannot drift apart on it silently.

do
  local path = require "kong.plugins.mudraid-enforce.path"
  local P = { "/mcp" }

  -- Exact, and descendants separated by "/".
  check(path.is_protected(P, "/mcp"), "boundary: the exact path is protected")
  check(path.is_protected(P, "/mcp/"), "boundary: a trailing slash is the same surface")
  check(path.is_protected(P, "/mcp/tools"), "boundary: a descendant is protected")
  check(path.is_protected(P, "/mcp//tools"),
    "boundary: an empty segment still lands inside the surface")

  -- Neighbours that merely share a character prefix. These are the defect.
  check(not path.is_protected(P, "/mcpfoo"),
    "boundary: /mcpfoo is a different route and is NOT protected")
  check(not path.is_protected(P, "/mcp-evil"),
    "boundary: /mcp-evil is a different route and is NOT protected")
  check(not path.is_protected(P, "/mcpevil/steal"),
    "boundary: a longer neighbour is NOT protected")
  check(not path.is_protected(P, "/mc"), "boundary: a shorter path is not protected")

  -- Query strings. Under the boundary rule "/mcp?x=1" is neither "/mcp" nor a
  -- "/mcp/" descendant, so stripping is what stops the tightening from opening
  -- a hole rather than being cosmetic.
  check(path.is_protected(P, "/mcp?x=1"), "boundary: a query string does not escape the surface")
  check(path.is_protected(P, "/mcp/tools?a=b"), "boundary: a query on a descendant is handled")
  check(path.is_protected(P, "/mcp#frag"), "boundary: a fragment does not escape the surface")
  eq(path.strip_query("/mcp?a=b"), "/mcp", "strip_query removes a query")
  eq(path.strip_query("/mcp#f"), "/mcp", "strip_query removes a fragment")
  eq(path.strip_query("/mcp"), "/mcp", "strip_query leaves a plain path alone")

  -- The encoded/traversal cases still hold: tightening one direction must not
  -- have loosened the other.
  check(path.is_protected(P, "/%6dcp/messages"), "boundary: encoded is still protected")
  check(path.is_protected(P, "/mcp/../mcp/tools"), "boundary: traversal is still protected")

  -- Root protects everything; it is the explicit spelling of "no exceptions".
  check(path.is_protected({ "/" }, "/anything/at/all"), "boundary: '/' protects every path")
  check(path.is_protected({ "/" }, "/"), "boundary: '/' protects the root itself")

  -- A configured trailing slash means the same surface.
  check(path.is_protected({ "/mcp/" }, "/mcp/tools"),
    "boundary: a configured trailing slash is normalized away")
  check(not path.is_protected({ "/mcp/" }, "/mcpfoo"),
    "boundary: a configured trailing slash does not restore the lexical match")

  -- matches_prefix directly, since it is the rule and is_protected is the sweep.
  check(path.matches_prefix("/mcp", "/mcp"), "matches_prefix: exact")
  check(path.matches_prefix("/mcp/x", "/mcp"), "matches_prefix: descendant")
  check(not path.matches_prefix("/mcpx", "/mcp"), "matches_prefix: neighbour refused")
  check(not path.matches_prefix("/mcp", ""), "matches_prefix: an empty prefix matches nothing")

  -- Multiple configured surfaces: each is tested on its own boundary.
  local MULTI = { "/mcp", "/rpc" }
  check(path.is_protected(MULTI, "/rpc/call"), "boundary: the second surface is protected")
  check(not path.is_protected(MULTI, "/rpcfoo"), "boundary: the second surface has a boundary too")
end

-- ---------------------------------------------------------------------------
-- HARDENING: an ambiguous protected-path CONFIG is refused, not resolved
-- ---------------------------------------------------------------------------
--
-- A request is hostile input and gets the benefit of every reading. A
-- configuration file is a statement of intent by someone who can simply write
-- the path they mean, so a prefix whose meaning depends on normalization is
-- refused at config load (schema.lua wires this to custom_validator).

do
  local path = require "kong.plugins.mudraid-enforce.path"
  local function reason(p)
    local ok, err = path.normalize_prefix(p)
    return ok or err
  end

  eq(reason("/mcp"), "/mcp", "prefix: a plain path is accepted unchanged")
  eq(reason("/mcp/"), "/mcp", "prefix: a trailing slash is stripped, not refused")
  eq(reason("/mcp///"), "/mcp", "prefix: repeated trailing slashes are stripped")
  eq(reason("/"), "/", "prefix: the root is a legitimate whole-surface declaration")
  eq(reason("/a/b/c"), "/a/b/c", "prefix: a deep path is accepted")

  check(reason("") ~= "", "prefix: empty is refused")
  check(reason("mcp"):find("absolute"), "prefix: a relative path is refused")
  check(reason("/mcp?x=1"):find("query"), "prefix: a query string is refused")
  check(reason("/mcp#f"):find("query"), "prefix: a fragment is refused")
  check(reason("/%6dcp"):find("percent"), "prefix: a percent-escape is refused, not decoded")
  check(reason("/mcp/../admin"):find("'%.'"), "prefix: a dot-dot segment is refused")
  check(reason("/mcp/./x"):find("'%.'"), "prefix: a dot segment is refused")
  check(reason("/mcp//x"):find("empty segment"), "prefix: an empty segment is refused")
  check(reason(nil) ~= nil, "prefix: a non-string is refused")
end

-- ---------------------------------------------------------------------------
-- HARDENING: canonical-serialization injectivity is CHECKED, not assumed
-- ---------------------------------------------------------------------------
--
-- containment.lua's header claims the NUL/US separators are excluded from every
-- value they join, "which is what keeps the serialization injective". Nothing
-- verified that on the verifying side. A signature is a statement about BYTES,
-- so a field carrying a separator makes one signature authenticate more than one
-- record — including one whose entries read back differently.

do
  local NUL = containment.FIELD_SEP
  local US = containment.ENTRY_SEP

  -- The concrete collision the check prevents: a crafted target_id that carries
  -- the rest of an entry, so one signed BLOCK can be read as a different entry
  -- set entirely.
  local smuggled = "victim" .. NUL .. "tenant" .. NUL .. "lift" .. NUL .. "1"
  eq(crefusal(csign(crecord({ entries = { centry({ target_id = smuggled }) } }))),
    "CONTAINMENT_ENTRY_INVALID",
    "a target_id carrying a field separator is refused before it can be trusted")

  eq(crefusal(csign(crecord({ entries = { centry({ target_id = "a" .. US .. "b" }) } }))),
    "CONTAINMENT_ENTRY_INVALID",
    "a target_id carrying an entry separator is refused")
  eq(crefusal(csign(crecord({ entries = { centry({ target_type = "plat" .. NUL .. "x" }) } }))),
    "CONTAINMENT_ENTRY_INVALID", "a target_type carrying a separator is refused")
  eq(crefusal(csign(crecord({ entries = { centry({ scope = "t" .. NUL .. "x" }) } }))),
    "CONTAINMENT_ENTRY_INVALID", "a scope carrying a separator is refused")
  eq(crefusal(csign(crecord({ entries = { centry({ reason_code = "r" .. NUL .. "x" }) } }))),
    "CONTAINMENT_ENTRY_INVALID", "a reason_code carrying a separator is refused")
  eq(crefusal(csign(crecord({ entries = { centry({ effective_at = "t" .. US .. "x" }) } }))),
    "CONTAINMENT_ENTRY_INVALID", "an effective_at carrying a separator is refused")

  -- The head is joined with the same bytes and gets the same treatment.
  eq(crefusal(csign(crecord({ organization_id = "org" .. NUL .. "other" }))),
    "CONTAINMENT_RESPONSE_INVALID", "an organization_id carrying a separator is refused")
  eq(crefusal(csign(crecord({ environment = "stag" .. US .. "prod" }))),
    "CONTAINMENT_RESPONSE_INVALID", "an environment carrying a separator is refused")

  -- The refusal is about AMBIGUITY, not about the signature: these records are
  -- correctly signed with the right secret and are still refused. That ordering
  -- is the point — a valid signature over ambiguous bytes is the problem.
  local signed_ambiguous = csign(crecord({ entries = { centry({ target_id = smuggled }) } }))
  local ok_sig = fake_crypto.hmac_sha256_hex(
    CONTAINMENT_FEED_SECRET, containment.canonical_bytes(signed_ambiguous))
  eq(signed_ambiguous.signature.digest, ok_sig,
    "the ambiguous record really is correctly signed (the refusal is not a sig failure)")

  -- Ordinary values keep working; this must not cost a legitimate feed anything.
  check(containment.verify(csign(crecord({ entries = { centry() } })), copts) ~= nil,
    "a record with ordinary values still verifies")

  -- The acknowledgement signs over the same join, from OPERATOR-supplied config.
  local applied = containment.apply(nil,
    containment.verify(csign(crecord({ entries = { centry() } })), copts))
  local ack_opts = {
    crypto = fake_crypto,
    secret = "ack-secret",
    adapter_id = "kong-a" .. NUL .. "kong-b",
    acknowledged_at = "2026-08-09T12:00:00+00:00",
  }
  local _, ack_code = containment.acknowledgement(applied, ack_opts)
  eq(ack_code, "CONTAINMENT_ACK_ADAPTER_ID_INVALID",
    "an adapter id carrying a separator is refused rather than signed")
  ack_opts.adapter_id = "kong-a"
  check(containment.acknowledgement(applied, ack_opts) ~= nil,
    "an ordinary adapter id still mints an acknowledgement")
end

-- ---------------------------------------------------------------------------



-- ---------------------------------------------------------------------------
-- Asymmetric bundle signature: absence vs invalidity.
-- ---------------------------------------------------------------------------
-- The single most important property in the migration window. A bundle with NO
-- asymmetric signature is a legacy bundle and rides on its HMAC. A bundle that
-- CARRIES one which does not verify is never treated as legacy — otherwise an
-- attacker holding the shared secret could corrupt one field and downgrade
-- every bundle to the weaker check.
local base64 = require "kong.plugins.mudraid-enforce.base64"

check(base64.decode("aGVsbG8=") == "hello", "b64decode decodes padded input")
check(base64.decode("aGVsbG8h") == "hello!", "b64decode decodes unpadded-length input")
check(base64.decode("aGVsbG8") == nil, "b64decode refuses a bad length")
-- Refused, never SKIPPED. ngx.decode_base64 silently drops invalid characters,
-- which would change the bytes being verified in an authentication tag.
check(base64.decode("aGVsb!8=") == nil, "b64decode refuses an invalid character")
check(base64.decode("") == nil, "b64decode refuses empty input")

check(bundle.SIGNATURE_PROFILE == "mudraid.bundle.signature/1",
  "the signature profile is pinned, not read from the bundle")
check(bundle.SIGNATURE_ALGORITHM == "RS256",
  "the signature algorithm is pinned to RS256")

-- ---------------------------------------------------------------------------
-- /decide response freshness: a decision is an answer about a MOMENT.
-- ---------------------------------------------------------------------------
-- The decision-id binding stops one request's answer being used for another.
-- Only freshness stops YESTERDAY's answer being used for today's — and that
-- matters more here than usual, because the id is echoed from the request, so
-- replaying a whole exchange pairs a stale allow with a fresh-looking id.
local decide_mod = require "kong.plugins.mudraid-enforce.decide"

check(decide_mod.parse_instant("2026-08-11T12:00:00Z") ==
      decide_mod.parse_instant("2026-08-11T12:00:00+00:00"),
  "Z and +00:00 are the same instant")
check(decide_mod.parse_instant("2026-08-11T12:00:00.123456+00:00") ==
      decide_mod.parse_instant("2026-08-11T12:00:00Z"),
  "fractional seconds are accepted and ignored")
-- 12:00+05:30 is 06:30 UTC, which is EARLIER in epoch terms. Getting the sign
-- backwards would make an eastward-offset decision look fresher than it is.
check(decide_mod.parse_instant("2026-08-11T12:00:00Z")
      - decide_mod.parse_instant("2026-08-11T12:00:00+05:30") == 19800,
  "a positive offset resolves earlier in epoch, not later")
-- Refused, not assumed UTC: the ambiguity is a whole timezone wide and the
-- guess errs toward admitting a stale allow.
check(decide_mod.parse_instant("2026-08-11T12:00:00") == nil,
  "a naive timestamp is refused rather than assumed UTC")
check(decide_mod.parse_instant("not-a-time") == nil, "garbage is refused")
check(decide_mod.parse_instant("") == nil, "an empty instant is refused")
check(decide_mod.parse_instant(nil) == nil, "an absent instant is refused")

-- The two adapters must agree, or portable enforcement has a gap that only
-- shows up on one gateway.
check(decide_mod.MAX_DECISION_AGE_SECONDS == 60,
  "the max decision age matches the Python middleware")
check(decide_mod.CLOCK_SKEW_SECONDS == 30,
  "the clock-skew allowance matches the Python middleware")

print(string.format("%d tests, %d failures", tests, failures))
if failures > 0 then
  os.exit(1)
end
