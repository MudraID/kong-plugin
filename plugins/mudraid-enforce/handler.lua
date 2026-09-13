-- mudraid-enforce: Kong enforcement-point plugin (EP-110-US-04, doc 03).
--
-- The Kong half of the V2 enforcement adapter (adapter_type
-- "kong_mudraid_enforce"). Responsibilities (doc 03 §7 "adapter owns"):
--
--   * background: poll the platform-integration adapter channel with the
--     per-adapter bearer token; verify HMAC signature + digests of every
--     served bundle BEFORE trusting it (bundle.lua); keep the last valid
--     bundle on any refusal; acknowledge received/validated/active facts
--     and validation errors (best-effort bounded spool, ack.lua);
--   * background: poll the signed CONTAINMENT projection from
--     enforcement-service, verify its HMAC before trusting it, apply it
--     ATOMICALLY and acknowledge the applied sequence (containment.lua,
--     doc 05 A05-06/A05-07);
--   * hot path, bundled surfaces only: strip client x-mudraid-* headers
--     FIRST (A03-04); bounded MCP framing + EXACT canonical action match
--     (A03-06/07); the containment projection is checked BEFORE any allow
--     and denies on a blocked target, a missing projection or one past its
--     maximum staleness (A05-06); live /decide required, deny-closed on
--     timeout/error/unmapped/no-bundle (A03-08/09/10); forward ONCE, upstream
--     retries disabled (A03-13); inject trusted context only after allow (§19);
--   * unmatched routes/paths pass through untouched.
--
-- WORKER MODEL (documented, honest): bundle state is per nginx worker.
-- Every worker polls and validates independently (the bundle swap is a
-- single table-reference assignment — atomic within a worker; a request
-- never mixes two bundle versions, A03-05). During a rollout, workers may
-- briefly run adjacent versions — bounded by one poll interval; this is
-- the mixed-version window doc 03 §20 requires the control plane to
-- report honestly, not hide. Bundle lifecycle acks are sent from worker 0
-- only (one representative report per instance); the first-observed-
-- decision fact is reported from whichever worker observes it first.
--
-- TENANT MODEL (multi-tenant step 3): per worker, state is a SET of
-- per-tenant slots keyed by declared surface, not one bundle. Each
-- configured plugin instance carries its own adapter credential, polls its
-- own slot on its own clock, and — on the hot path — resolves its own
-- bundle by key with NO fallback. tenants.lua owns the set, the selection
-- rule and the reasoning; read it before changing anything here.
--
-- CLAIM LANGUAGE (A03-14/P00): nothing in this plugin claims "enforced"
-- or "verified" — it reports received/validated/active/observed facts and
-- lets the control-plane ladder speak.

local bundle_mod = require "kong.plugins.mudraid-enforce.bundle"
local matcher = require "kong.plugins.mudraid-enforce.matcher"
local headers_mod = require "kong.plugins.mudraid-enforce.headers"
local ack_mod = require "kong.plugins.mudraid-enforce.ack"
local channel = require "kong.plugins.mudraid-enforce.channel"
local tenants = require "kong.plugins.mudraid-enforce.tenants"
local decide = require "kong.plugins.mudraid-enforce.decide"
local execution_mod = require "kong.plugins.mudraid-enforce.execution"
local containment = require "kong.plugins.mudraid-enforce.containment"
local crypto = require "kong.plugins.mudraid-enforce.crypto"
local path_mod = require "kong.plugins.mudraid-enforce.path"
local cjson = require "cjson.safe"

local MudraidEnforce = {
  -- After rate-limiting (910), before request-transformer (801): the strip
  -- performed here is surface-scoped and bundle-driven; the global
  -- request-transformer strip remains the deployment-wide floor.
  PRIORITY = 900,
  VERSION = "1.1.0",
}

local ADAPTER_TYPE = "kong_mudraid_enforce"

-- ---------------------------------------------------------------------------
-- Per-worker state
-- ---------------------------------------------------------------------------

-- Everything that used to be a single field here is now PER TENANT SLOT
-- (tenants.lua): the bundle, the poll clock, the ack spool, the once-only log
-- latches and the first-observed-decision fact. Each is a per-ADAPTER fact —
-- the ack carrying it is posted with that adapter's own credential — so one
-- shared copy would misattribute it across tenants rather than merely blur it.
--
-- `report_seq` stays here on purpose: it is a worker-local uniqueness counter
-- for report ids, not a statement about any tenant, and keeping one sequence
-- means two slots can never mint the same id in the same second.
local state = {
  confs = nil,           -- ALL instances, captured by configure(); timers read each tick
  set = tenants.new(),   -- key -> slot, plus the admitted/refused plan
  report_seq = 0,
}

local function iso_now()
  return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

-- Stable per-report id (charset/length per the channel's REPORT_ID_PATTERN
-- ^[A-Za-z0-9._-]{8,64}$). Assigned once at enqueue time and kept across
-- delivery retries so a retried POST is a server-side replay, never a
-- duplicate row.
local function next_report_id()
  state.report_seq = state.report_seq + 1
  return string.format(
    "kong.w%d.%d.%d", ngx.worker.id() or 0, ngx.time(), state.report_seq)
end

local function uuid()
  local ok, lib = pcall(require, "kong.tools.uuid")
  if ok and lib.uuid then
    return lib.uuid()
  end
  local ok2, utils = pcall(require, "kong.tools.utils")
  if ok2 and utils.uuid then
    return utils.uuid()
  end
  -- Last-resort fallback (never expected in Kong): time+random tag.
  return string.format("%08x-%04x-%04x", ngx.time(), math.random(0xffff), math.random(0xffff))
end

local function enqueue_ack(slot, report)
  report.report_id = next_report_id()
  report.adapter_version = MudraidEnforce.VERSION
  ack_mod.push(slot.spool, report)
end

-- ---------------------------------------------------------------------------
-- Background: bundle poll + ack drain (timer context, never the hot path)
-- ---------------------------------------------------------------------------

-- The spool is drained with the conf that OWNS it. An ack is a statement made
-- by one adapter about its own bundle, authenticated with that adapter's
-- credential; posting a slot's reports on another slot's channel would file
-- one tenant's facts against another tenant's adapter row.
local function drain_spool(conf, slot)
  if ack_mod.size(slot.spool) == 0 then
    return
  end
  ack_mod.drain(slot.spool, function(report)
    local ok, note = channel.post_ack(conf, report)
    if ok and note then
      kong.log.warn("mudraid-enforce: ack ", report.report_id, " ", note)
    end
    return ok
  end)
  if slot.spool.dropped > 0 then
    -- Measured loss is surfaced, never hidden (see ack.lua limitation).
    kong.log.warn("mudraid-enforce: ack spool dropped ", slot.spool.dropped,
      " report(s) total for surface ", slot.key,
      " (bounded in-memory spool; durable spooling is EP-230/Audit)")
  end
end

-- A tenancy refusal at poll time: the bundle is NOT swapped in, the slot keeps
-- whatever it already had (or keeps failing closed with nothing), and the fact
-- is acknowledged on that adapter's own channel.
local function refuse(slot, code, detail)
  kong.log.err("mudraid-enforce: bundle refused for surface ", slot.key,
    ": ", code, " (", detail, ")")
  if (ngx.worker.id() or 0) == 0 then
    enqueue_ack(slot, { error_code = code, error_detail = detail })
  end
end

local function poll_bundle(conf, slot)
  -- A9-02: refresh the DECISION-response verification keys alongside the
  -- bundle. Never clears a working set — the keys are public, already-fetched
  -- material, and dropping them because the endpoint blipped would refuse
  -- every SIGNED decision, turning a transient control-plane outage into an
  -- enforcement outage. Rotation still takes effect because a successful
  -- fetch REPLACES the set: a key that stops being published stops being
  -- trusted at the next successful refresh. (Mirrors the Python middleware's
  -- _refresh_verification_keys discipline.)
  local decision_keys, kerr = channel.fetch_verification_keys(conf)
  if decision_keys then
    if next(decision_keys) ~= nil then
      slot.decision_keys = decision_keys
    end
  elseif kerr then
    kong.log.warn("mudraid-enforce: verification keys fetch failed: ", kerr)
  end

  local active = slot.bundle and {
    bundle_version = slot.bundle.bundle_version,
    payload_digest = slot.bundle.payload_digest,
  } or nil

  -- Heartbeat first: cheap, keeps last_seen_at measured server-side, and
  -- tells us whether a fetch is even needed.
  local hb, hb_err = channel.heartbeat(conf)
  if hb then
    -- The server's OWN attribution of this credential to a platform. Step 2
    -- (§4) established this is the trustworthy statement of tenant identity —
    -- the payload's claim is signed with an HMAC every tenant shares, so it
    -- proves the platform signed a bundle, never whose it is.
    local conflict = tenants.attribution_conflict(slot.key, hb.platform_id, nil)
    if not conflict and slot.attributed_platform_id
      and slot.attributed_platform_id ~= hb.platform_id then
      -- The same instance's credential now answers as a DIFFERENT platform.
      -- The only ways that happens are a swapped secret or a re-pointed
      -- adapter row; neither is a state to keep serving through.
      conflict = "attribution_changed"
    end
    if conflict then
      refuse(slot, "BUNDLE_TENANCY_CONFLICT",
        conflict .. " (declared " .. tostring(slot.key)
        .. ", attributed " .. tostring(hb.platform_id) .. ")")
      return
    end
    slot.attributed_platform_id = hb.platform_id

    local desired_v = hb.desired_bundle_version
    if type(desired_v) ~= "number" then
      return -- nothing published yet; keep polling quietly
    end
    if active and desired_v == active.bundle_version
      and hb.desired_payload_digest == active.payload_digest then
      return -- already current
    end
  else
    kong.log.warn("mudraid-enforce: heartbeat failed: ", hb_err)
    -- Fall through to a fetch attempt anyway: at bootstrap (no bundle at
    -- all) a fetch is worth one try even when the heartbeat failed.
    if active then
      return
    end
  end

  local fetched, ferr = channel.fetch_bundle(conf)
  if not fetched then
    if ferr ~= "no_bundle_published" then
      kong.log.warn("mudraid-enforce: bundle fetch failed: ", ferr)
    end
    return
  end

  local verified, code, detail = bundle_mod.verify(fetched, {
    crypto = crypto,
    secret = conf.bundle_signing_secret,
    json = { null = channel.null, array_mt = channel.array_mt },
    active = active,
  })
  if not verified then
    -- Refused: last valid bundle stays active; if none exists, bundled
    -- surfaces keep failing CLOSED. The refusal is an acknowledged fact.
    refuse(slot, code, detail)
    return
  end
  if verified.no_change then
    return
  end

  -- Step 4's narrowed check (step 2 §4): the surface the DEPLOYMENT declared,
  -- the surface the SERVER attributed to this credential, and the surface the
  -- signed payload CLAIMS must all agree. Signature validity carries none of
  -- the weight it appears to here — one shared HMAC signs every tenant — so a
  -- bundle for the wrong surface verifies perfectly and must be caught on
  -- identity, not on cryptography. This should never fire.
  local claimed = verified.payload and verified.payload.content
    and verified.payload.content.surface
    and verified.payload.content.surface.platform_id or nil
  local conflict = tenants.attribution_conflict(
    slot.key, slot.attributed_platform_id, claimed)
  if conflict then
    refuse(slot, "BUNDLE_TENANCY_CONFLICT",
      conflict .. " (attributed " .. tostring(slot.attributed_platform_id)
      .. ", payload claims " .. tostring(claimed) .. ")")
    return
  end

  -- Atomic swap: one assignment; in-flight requests hold their own
  -- reference and finish on the version they started with (A03-05).
  slot.bundle = verified
  slot.no_bundle_logged = false
  kong.log.notice("mudraid-enforce: activated bundle version ",
    verified.bundle_version, " (payload_digest ", verified.payload_digest,
    ", key ", verified.signing_key_id, ", ",
    #verified.actions, " action(s))")

  if (ngx.worker.id() or 0) == 0 then
    local now = iso_now()
    -- received/validated/active are reported together because this
    -- adapter validates-then-swaps in one pass; each is still its own
    -- fact server-side and none of them claims "enforced".
    enqueue_ack(slot, {
      received_version = verified.bundle_version,
      received_at = now,
      validated_version = verified.bundle_version,
      validated_at = now,
      active_version = verified.bundle_version,
      active_at = now,
      bundle_digest = verified.payload_digest,
    })
  end
end

-- ---------------------------------------------------------------------------
-- Background: signed containment projection (A05-06)
-- ---------------------------------------------------------------------------

local function containment_configured(conf)
  return type(conf.containment_feed_url) == "string" and conf.containment_feed_url ~= ""
end

-- Deliver the pending containment acknowledgement, if any. ONE pending ack per
-- slot rather than a spool: acknowledgements are cumulative — a later sequence
-- supersedes an earlier one entirely — so queuing the intermediate ones would
-- deliver facts the server has already been told by a newer row. It is retried
-- on every tick until accepted; the server dedups on (adapter, sequence), so a
-- retry is a replay and never a duplicated measurement.
local function drain_containment_ack(conf, slot)
  if not slot.pending_containment_ack then
    return
  end
  local ok, note = channel.post_containment_ack(conf, slot.pending_containment_ack)
  if ok then
    slot.pending_containment_ack = nil
    return
  end
  if note == "containment_ack_signature_rejected" then
    -- Retrying cannot fix a rejected signature; it is a shared-secret
    -- misconfiguration. Drop it and say so, rather than retrying every tick
    -- forever behind a message no one reads.
    kong.log.err("mudraid-enforce: containment acknowledgement REJECTED for surface ",
      slot.key, " (ack ingest secret disagrees with enforcement-service); ",
      "this adapter cannot be counted as converged until it is fixed")
    slot.pending_containment_ack = nil
    return
  end
  kong.log.warn("mudraid-enforce: containment acknowledgement not delivered for surface ",
    slot.key, ": ", tostring(note))
end

local function poll_containment(conf, slot)
  local fetched, ferr = channel.fetch_containment(conf)
  if not fetched then
    if ferr ~= "no_containment_feed_published" then
      kong.log.warn("mudraid-enforce: containment feed fetch failed for surface ",
        slot.key, ": ", ferr)
    end
    -- The last verified projection stays applied and keeps ageing against its
    -- maximum staleness. It is NOT cleared and NOT extended: a disconnected
    -- adapter runs on what it has until freshness expires, then denies.
    return
  end

  local verified, code, detail = containment.verify(fetched, {
    crypto = crypto,
    secret = conf.containment_feed_signing_secret,
    key_id = conf.containment_feed_signing_key_id,
    active = slot.containment,
  })
  if not verified then
    -- Refused: the last verified projection stays applied; if none exists,
    -- protected actions keep failing CLOSED. The refusal is an acknowledged
    -- fact on this adapter's own channel, like a bundle refusal.
    refuse(slot, code, detail)
    return
  end
  if verified.no_change then
    return
  end

  local applied, acode, adetail = containment.apply(slot.containment, verified)
  if not applied then
    refuse(slot, acode, adetail)
    return
  end

  -- ATOMIC: one table-reference assignment. containment.apply built a whole
  -- new projection without touching the old one, so an in-flight request sees
  -- either the complete previous projection or the complete new one — never a
  -- partially applied set of block entries (A05-06 "apply updates atomically").
  slot.containment = applied
  slot.containment_unavailable_logged = false
  kong.log.notice("mudraid-enforce: applied containment projection sequence ",
    applied.sequence, " for surface ", slot.key, " (", applied.block_count,
    " block(s), key ", applied.signing_key_id, ")")
  if applied.unevaluable > 0 then
    -- Measured, never hidden: blocks this adapter cannot bind a pre-/decide
    -- request to. They remain covered by the authoritative live /decide check,
    -- and this number is how big that reliance is.
    kong.log.notice("mudraid-enforce: ", applied.unevaluable,
      " containment block(s) on surface ", slot.key,
      " name target types this adapter cannot bind pre-/decide; ",
      "they are enforced by the live decision path only")
  end

  local ack, ecode, edetail = containment.acknowledgement(applied, {
    crypto = crypto,
    adapter_id = conf.containment_adapter_id,
    secret = conf.containment_ack_signing_secret,
    key_id = conf.containment_ack_signing_key_id,
    acknowledged_at = containment.iso_utc_offset(ngx.time()),
  })
  if not ack then
    -- The projection IS applied and enforced; only the convergence claim is
    -- unavailable. Those are different facts and are not collapsed.
    if not slot.containment_ack_logged then
      slot.containment_ack_logged = true
      kong.log.err("mudraid-enforce: containment projection applied but NOT ",
        "acknowledgeable for surface ", slot.key, ": ", ecode, " (", edetail, ")")
    end
    return
  end
  slot.pending_containment_ack = ack
end

-- One instance's turn. Wrapped per instance rather than per tick so that one
-- tenant's channel erroring cannot stop the remaining tenants from polling —
-- the partial-refresh independence tenants.lua describes has to hold in the
-- scheduler too, not only in the lookup.
local function tick_one(conf)
  local slot = tenants.slot(state.set, tenants.key_for(conf))
  if not slot.spool then
    slot.spool = ack_mod.new(conf.ack_spool_max or 256)
  end

  drain_spool(conf, slot)

  -- Containment runs on its OWN clock and its own credential set, before the
  -- bundle gate below: an adapter whose bundle credentials are missing still
  -- has to keep its containment projection fresh, because a stale projection
  -- is a deny and the operator has to be able to see which of the two is
  -- actually broken.
  if containment_configured(conf) then
    drain_containment_ack(conf, slot)
    if ngx.now() - (slot.last_containment_poll or 0) >= conf.containment_poll_interval_seconds then
      slot.last_containment_poll = ngx.now()
      poll_containment(conf, slot)
    end
  elseif not slot.containment_unconfigured_logged then
    slot.containment_unconfigured_logged = true
    -- A05-07 names this exact state and refuses to let it hide inside a fleet
    -- claim: an adapter with no V2 containment feed retains token/cache
    -- exposure. Said once, plainly, rather than implied by silence.
    kong.log.warn("mudraid-enforce: no containment feed configured for surface ", slot.key,
      "; this adapter is OUTSIDE the V2 containment feed and its revocation ",
      "exposure is bounded by token/cache lifetime only (doc 05 A05-07)")
  end

  if not (conf.adapter_token and conf.adapter_token ~= ""
    and conf.bundle_signing_secret and conf.bundle_signing_secret ~= "") then
    if not slot.unconfigured_logged then
      slot.unconfigured_logged = true
      kong.log.warn("mudraid-enforce: adapter_token/bundle_signing_secret not configured ",
        "for surface ", slot.key,
        "; no bundle can be loaded and protected paths fail CLOSED (503)")
    end
    return
  end
  if ngx.now() - slot.last_poll < conf.poll_interval_seconds then
    return
  end
  slot.last_poll = ngx.now()
  poll_bundle(conf, slot)
end

local function tick(premature)
  if premature then
    return
  end
  local confs = state.confs
  if not confs then
    return
  end
  for i = 1, #confs do
    local ok, err = pcall(tick_one, confs[i])
    if not ok then
      kong.log.err("mudraid-enforce: poll tick error: ", err)
    end
  end
end

function MudraidEnforce:init_worker()
  -- Spools are created per slot on first tick, once the owning conf is known
  -- (ack_spool_max is per instance).
  --
  -- One short-period timer per worker; actual poll cadence is
  -- conf.poll_interval_seconds (checked inside tick, so declarative config
  -- reloads take effect without re-arming timers). One timer still serves ALL
  -- tenants: each slot keeps its own clock, so N tenants share the tick rather
  -- than arming N timers.
  ngx.timer.every(5, tick)
end

-- Kong 3.4+ calls configure() on every declarative config (re)load with ALL
-- instances of this plugin. This used to take configs[1] and let it drive the
-- single background channel loop, which is exactly why a second instance could
-- not have its own bundle.
--
-- It is also the only place the whole fleet is visible at once, so it is where
-- the admitted/refused plan is computed: two instances declaring the same
-- surface, or an undeclared surface once there is more than one instance, are
-- both unresolvable and both refuse. Neither can be detected from inside a
-- single request.
function MudraidEnforce:configure(configs)
  state.confs = configs or {}
  state.set.plan = tenants.plan(state.confs)

  for i = 1, #state.confs do
    local conf = state.confs[i]
    local slot = tenants.slot(state.set, tenants.key_for(conf))
    if slot.spool then
      slot.spool.max = conf.ack_spool_max
    end
    slot.unconfigured_logged = false
  end

  for key, reason in pairs(state.set.plan.refusals) do
    kong.log.err("mudraid-enforce: surface ", key, " is REFUSED (", reason,
      "); protected requests on it fail CLOSED until the configuration is fixed")
  end
end

-- ---------------------------------------------------------------------------
-- Hot path
-- ---------------------------------------------------------------------------

-- Is this request on a declared bundled surface?
--
-- Tested against EVERY spelling of the path (path.lua): the raw one, the
-- percent-decoded one and the dot-segment-resolved one. A match on any of them
-- is protected.
--
-- The reason is a disagreement between two layers of the same gateway.
-- `kong.request.get_path()` returns the RAW path — the PDK slices
-- `ngx.var.request_uri` at the "?" — while Kong's ROUTER matched a normalized
-- one to get here. So `/%6dcp/messages` and `/mcp/../mcp/messages` both route to
-- the protected upstream and both used to fail this byte prefix compare, and
-- failing it does not deny: it RETURNS EARLY, skipping the header strip, the
-- framing bound, the containment check and /decide, then forwards the request
-- to the protected upstream untouched.
--
-- Taking the union rather than swapping raw for normalized keeps the direction
-- safe: this can only classify MORE requests as protected, never fewer. A
-- mistake here costs an unprotected request a decision it did not need; the
-- mistake it replaces cost a protected request every check the plugin exists to
-- perform.
--
-- The predicate lives in path.lua, which has no ngx/Kong dependency, so the
-- gate that decides whether the whole control loop runs is exercised by the
-- test harness directly rather than through a copy of itself.
local is_protected = path_mod.is_protected

-- Bound on a correlation id echoed back to the caller or forwarded to /decide.
-- Long enough for a UUID, a W3C trace id or any sane opaque token.
local MAX_CORRELATION_ID_LEN = 200

--- The caller's correlation id, if it is one we are willing to repeat.
--
-- The value is CLIENT-SUPPLIED and it travels two ways: back to the caller in
-- every typed denial, and onward to /decide in the decision envelope. Neither
-- destination should receive an unbounded attacker-chosen string. Restricting
-- it to a bounded run of visible ASCII keeps it useful for the thing it is for —
-- correlating one request across logs — and refuses the rest by returning nil,
-- which reads as "no correlation id", the same as not sending one.
--
-- This is deliberately narrower than "whatever nginx accepted in a header": the
-- id is copied into a JSON body and into an outbound header, and each consumer
-- downstream has its own idea of what is safe to render. A bounded token
-- sidesteps all of those questions at once.
local function safe_correlation_id()
  local raw = kong.request.get_header("X-Correlation-ID")
  if type(raw) ~= "string" or raw == "" then
    return nil
  end
  if #raw > MAX_CORRELATION_ID_LEN then
    return nil
  end
  if raw:match("^[A-Za-z0-9._:%-]+$") == nil then
    return nil
  end
  return raw
end

-- Typed denial. Bodies are structural (code/message/ids) — no upstream
-- detail, no token material, no tool arguments (doc 03 §22).
local function deny(status_code, code, message, decision_id)
  return kong.response.exit(status_code, {
    error = {
      code = code,
      message = message,
      correlation_id = safe_correlation_id(),
      decision_id = decision_id,
    },
  }, { ["Content-Type"] = "application/json" })
end

-- The ceiling Kong's PDK enforces on get_headers; it REFUSES a larger value, so
-- this is not a number we can raise our way out of.
local MAX_ENUMERABLE_HEADERS = 1000

-- Names this plugin injects itself. Cleared unconditionally, by exact name,
-- BEFORE the prefix sweep — see strip_reserved_headers.
local SELF_INJECTED_HEADERS = {
  "X-MudraID-Decision-Id",
  "X-MudraID-Bundle-Version",
  "X-MudraID-Action-Key",
}

--- Strip client-supplied reserved headers (A03-04).
--
-- Returns false when the header set could not be enumerated completely, which
-- the caller turns into a deny-closed 503.
--
-- WHY COMPLETENESS IS A SECURITY PROPERTY HERE. The strip works by ENUMERATING
-- the request's headers and clearing the ones that match a prefix. Enumeration
-- is bounded — `get_headers(1000)`, and Kong's PDK rejects a limit above that —
-- and OpenResty TRUNCATES at the bound rather than failing. A client that sends
-- 1000 filler headers followed by `X-MudraID-Decision-Id: <forged>` therefore
-- gets a forged trusted-context header that is never enumerated, never matched,
-- never cleared, and forwarded to an upstream whose entire reason for trusting
-- that header is that this plugin promised to have removed it. Nginx's default
-- `large_client_header_buffers` (4 x 8k) leaves room for well over a thousand
-- short headers, so the flood is ordinary traffic, not a tuned edge case.
--
-- Two answers, because they cover different halves:
--
--   1. The three names this plugin injects are cleared by EXACT NAME first.
--      `clear_header` does not require the header to have been enumerated, so
--      this half holds no matter how many headers arrive.
--   2. Truncation is DETECTED and denies. The exact-name clear cannot cover the
--      bundle's configurable prefix list — an operator may widen it, and those
--      names are not known here — so an incomplete enumeration means the strip
--      cannot be shown to have happened. "Cannot be shown" is the plugin's
--      standing definition of not safely decided, and it denies, as it does for
--      an unreadable body or a missing bundle.
local function strip_reserved_headers(active_bundle)
  -- (1) Unconditional, enumeration-independent floor.
  for i = 1, #SELF_INJECTED_HEADERS do
    kong.service.request.clear_header(SELF_INJECTED_HEADERS[i])
  end

  local prefixes = headers_mod.effective_prefixes(
    active_bundle and active_bundle.strip_prefixes or nil)
  -- The PDK forwards ngx.req.get_headers' second return, which is "truncated"
  -- when the bound was hit. Read it rather than assuming the table is complete.
  local req_headers, enum_err = kong.request.get_headers(MAX_ENUMERABLE_HEADERS)
  if type(req_headers) ~= "table" then
    return false
  end

  local seen = 0
  for name in pairs(req_headers) do
    seen = seen + 1
    if headers_mod.should_strip(name, prefixes) then
      kong.service.request.clear_header(name)
    end
  end

  -- Belt and braces on the detection itself: a PDK that swallowed the second
  -- return value would report nothing, so a full table is ALSO treated as
  -- possibly truncated. At the bound we cannot distinguish "exactly 1000
  -- headers" from "1000 and then some", and only one of those is safe.
  if enum_err ~= nil or seen >= MAX_ENUMERABLE_HEADERS then
    return false
  end
  return true
end

local function observe_decision_once(slot)
  if slot and not slot.decision_observed then
    slot.decision_observed = true
    -- A real request used a decision path — a historical fact the control
    -- plane records as first_observed_decision_at (any outcome counts).
    enqueue_ack(slot, { first_observed_decision_at = iso_now() })
  end
end

function MudraidEnforce:access(conf)
  local path = kong.request.get_path()
  if not is_protected(conf.protected_paths, path) then
    -- Not a bundled surface: pass through untouched.
    return
  end

  -- SELECTION FIRST. This is a pure table lookup keyed on THIS instance's
  -- declared surface — no I/O, so putting it ahead of the strip costs nothing
  -- and changes no failure semantics.
  --
  -- It has to come first. `strip_reserved_headers` reads its prefix list from
  -- the bundle, so stripping before selection would strip against whichever
  -- bundle happened to be sitting in a shared field — another tenant's, under
  -- Option B. A03-04 still holds in full: the strip runs before any check,
  -- extraction, matching or /decide, and on requests that will be denied.
  local b, refusal, key = tenants.select(state.set, conf)
  local slot = state.set.slots[key]

  if not strip_reserved_headers(b) then
    -- The header set could not be enumerated completely, so the A03-04 strip
    -- cannot be shown to have run. Deny-closed, ahead of the bundle refusals
    -- below: this is true regardless of which bundle would have answered, and
    -- forwarding a request whose reserved headers may be client-supplied is the
    -- one outcome the trusted-context contract forbids outright.
    kong.log.err("mudraid-enforce: request header set exceeds the enumerable bound on ",
      "surface ", key, "; the reserved-header strip cannot be verified, denying closed")
    return deny(503, "ENFORCE_HEADER_SET_UNBOUNDED",
      "The request presented more headers than can be inspected; it was not evaluated.")
  end

  if not b then
    -- Fail CLOSED. The three refusal reasons are kept distinct in the log
    -- because two of them are MISCONFIGURATIONS that will never clear on their
    -- own, and reporting them as the ordinary cold-start state would leave an
    -- operator waiting for a poll that is never going to fix it.
    if slot and not slot.no_bundle_logged then
      slot.no_bundle_logged = true
      kong.log.err("mudraid-enforce: denying protected traffic on surface ", key,
        ": ", refusal)
    elseif not slot then
      kong.log.err("mudraid-enforce: denying protected traffic on surface ", key,
        ": ", refusal)
    end
    if refusal == tenants.AMBIGUOUS then
      return deny(503, "ENFORCE_SURFACE_AMBIGUOUS",
        "More than one enforcement surface is configured for this identifier; "
        .. "protected requests fail closed rather than resolving one of them.")
    end
    if refusal == tenants.UNIDENTIFIED then
      return deny(503, "ENFORCE_SURFACE_UNIDENTIFIED",
        "This route declares no enforcement surface; protected requests fail closed.")
    end
    return deny(503, "ENFORCE_NO_VALID_BUNDLE",
      "No valid signed enforcement bundle is active; protected requests fail closed.")
  end

  local method = kong.request.get_method()
  if method == "GET" or method == "HEAD" or method == "OPTIONS" or method == "DELETE" then
    -- MCP Streamable HTTP control traffic (SSE stream open, session
    -- delete, preflight) carries no JSON-RPC request and cannot invoke a
    -- tool; classified control-plane (A03-08), passed through.
    return
  end
  if method ~= "POST" then
    return deny(405, "ENFORCE_METHOD_NOT_ALLOWED",
      "Only MCP Streamable HTTP methods are accepted on this protected surface.")
  end

  -- Bounded framing (A03-07): never buffer unbounded input to find an
  -- action; oversized/unreadable bodies deny, never partially evaluate.
  local body, body_err = kong.request.get_raw_body()
  if not body then
    if body_err and body_err:find("buffer", 1, true) then
      return deny(413, "ENFORCE_BODY_TOO_LARGE",
        "Request body exceeds the bounded evaluation limit.")
    end
    return deny(400, "ENFORCE_BODY_UNREADABLE", "Request body could not be read for evaluation.")
  end
  if #body > conf.request_body_max_bytes then
    return deny(413, "ENFORCE_BODY_TOO_LARGE",
      "Request body exceeds the bounded evaluation limit.")
  end

  -- Parse JSON exactly once (A03-07).
  local msg = cjson.decode(body)
  if type(msg) ~= "table" then
    return deny(400, "ENFORCE_MALFORMED_REQUEST",
      "Protected surface requires a JSON-RPC 2.0 request body.")
  end
  if msg[1] ~= nil then
    -- Batching is not a declared capability: rejected, not partially
    -- evaluated (A03-07 — one decision never authorizes a batch).
    return deny(400, "ENFORCE_BATCH_UNSUPPORTED",
      "JSON-RPC batch requests are not supported on this protected surface.")
  end
  if msg.jsonrpc ~= "2.0" or type(msg.method) ~= "string" or msg.method == "" then
    return deny(400, "ENFORCE_MALFORMED_REQUEST",
      "Protected surface requires a JSON-RPC 2.0 request body.")
  end

  if msg.method ~= "tools/call" then
    -- Non-tool protocol messages are separately classified (A03-07):
    -- allowlisted control/discovery methods and client notifications pass;
    -- everything else on a protected surface denies rather than slipping
    -- through because extraction found no action.
    if msg.method:sub(1, 14) == "notifications/" then
      return
    end
    for i = 1, #conf.public_methods do
      if msg.method == conf.public_methods[i] then
        return
      end
    end
    return deny(403, "ENFORCE_MESSAGE_NOT_ALLOWED",
      "This protocol message is not permitted on the protected surface.")
  end

  -- Exact canonical action resolution — never fuzzy (A03-06/07).
  local tool_name = type(msg.params) == "table" and msg.params.name or nil
  local action, why = matcher.resolve(b.matcher_index, tool_name)
  if not action then
    observe_decision_once(slot)
    if why == "invalid_name" then
      return deny(400, "ENFORCE_MALFORMED_REQUEST",
        "tools/call params.name must be a non-empty bounded string.")
    end
    -- on_unmapped_action = deny (bundle contract): a consequential call
    -- without a confirmed mapping is blocked, with remediation belonging
    -- to the operator surface, not this response.
    return deny(403, "ENFORCE_ACTION_UNMAPPED",
      "No active canonical action is mapped for this tool on this surface.")
  end

  local surface = b.payload.content.surface

  -- ---------------------------------------------------------------------
  -- Containment: checked BEFORE any allow (doc 05 A05-06)
  -- ---------------------------------------------------------------------
  --
  -- Placed here, and not earlier, for two reasons. It needs the exactly
  -- matched canonical action to evaluate action-scoped blocks, and everything
  -- above it is either a pass-through classification (control-plane MCP
  -- traffic, which authorizes no protected action) or a refusal. A03-04 is
  -- untouched: strip_reserved_headers already ran, before any check,
  -- extraction, matching or /decide, and on requests that will be denied.
  --
  -- Every subject candidate below comes from HMAC-VERIFIED material only —
  -- the signed bundle's surface binding and the matched action — never from a
  -- client header. Containment that a client could rename itself out of would
  -- not be containment.
  if containment_configured(conf) then
    -- Named apart from the matcher's `why` above rather than shadowing it: two
    -- different refusal explanations in one function is exactly where a later
    -- edit reports the wrong one.
    local contained, contained_why = containment.evaluate(slot and slot.containment, {
      { target_type = "platform", target_id = surface and surface.platform_id or nil },
      { target_type = "resource", target_id = surface and surface.canonical_resource_uri or nil },
      { target_type = "action", target_id = action.action_key },
    }, {
      now = ngx.time(),
      max_staleness_seconds = conf.containment_max_staleness_seconds,
      clock_skew_seconds = conf.containment_clock_skew_seconds,
    })
    if contained ~= containment.CLEAR then
      observe_decision_once(slot)
      if contained == containment.BLOCKED then
        kong.log.warn("mudraid-enforce: containment BLOCK on surface ", key,
          " (", contained_why.target_type, " ", contained_why.target_id, ", scope ", contained_why.scope,
          ", reason ", contained_why.reason_code, ", sequence ", contained_why.sequence, ")")
        return deny(403, "ENFORCE_CONTAINMENT_BLOCKED",
          "This action is contained for the named target and is not permitted.")
      end
      if contained == containment.STALE then
        -- A05-06: the last projection is usable only within the configured
        -- maximum staleness. Past it the action denies rather than continuing
        -- indefinitely on a projection that may be missing a block.
        kong.log.err("mudraid-enforce: containment projection STALE on surface ", key,
          " (age ", tostring(contained_why.age_seconds), "s > max ",
          tostring(contained_why.max_staleness_seconds), "s, sequence ", tostring(contained_why.sequence),
          "); denying closed")
        return deny(503, "ENFORCE_CONTAINMENT_STALE",
          "The containment projection for this surface is not fresh enough to "
          .. "authorize this action; protected requests fail closed.")
      end
      -- UNAVAILABLE. Not "nothing is contained" — nothing is KNOWN.
      if slot and not slot.containment_unavailable_logged then
        slot.containment_unavailable_logged = true
        kong.log.err("mudraid-enforce: no verified containment projection on surface ", key,
          " (", contained_why.reason, "); protected requests fail closed")
      end
      return deny(503, "ENFORCE_CONTAINMENT_UNAVAILABLE",
        "No verified containment projection is available for this surface; "
        .. "protected requests fail closed.")
    end
  end

  -- Live /decide — required for every protected call (bundle contract:
  -- decide_required=true; snapshot mode has no conformance story yet).
  --
  -- This is also the AUTHORITATIVE containment check (A05-06: "live /decide
  -- checks the authoritative current projection/source"). The local projection
  -- above is a stricter, earlier gate over the targets this adapter can bind;
  -- it never replaces this call, and no allow is returned without it.
  local execution_digest, execution
  local decision_path = path
  if action.argument_profile ~= nil and action.argument_profile ~= cjson.null then
    decision_path = ngx.var.request_uri
    local ok, digest, snapshot = pcall(execution_mod.bind, b, action, {
      body = body, content_type = kong.request.get_header("Content-Type"),
      authorization = kong.request.get_header("Authorization"),
      method = method, path = decision_path,
    }, {
      crypto = crypto, json = { null = channel.null, array_mt = channel.array_mt },
      encode_base64 = ngx.encode_base64,
    })
    if not ok or not digest then
      return deny(503, "ENFORCE_DECIDE_UNAVAILABLE",
        "The request could not be bound to its configured conditions.")
    end
    execution_digest, execution = digest, snapshot
  end
  local decision_id = uuid()
  local outcome, detail = decide.call(conf, {
    schema_version = decide.ENVELOPE_SCHEMA,
    decision_id = decision_id,
    -- Bounded/validated (safe_correlation_id): this value is client-supplied and
    -- is about to be written into an outbound header on the /decide call.
    correlation_id = safe_correlation_id(),
    adapter = { type = ADAPTER_TYPE, version = MudraidEnforce.VERSION },
    bundle = { version = b.bundle_version, payload_digest = b.payload_digest },
    -- Forward the full HMAC-verified bundle surface binding (A6-P1-01 / M2):
    -- platform_id + environment + canonical_resource_uri. These come only from
    -- the signed bundle content, never from client headers.
    --
    -- AUDIT-006 M4: all three are GUARANTEED non-empty strings here —
    -- bundle.verify refuses any bundle whose content.surface leaves one
    -- absent, null or blank (BUNDLE_SURFACE_UNBOUND), so an active bundle
    -- cannot produce a /decide envelope with a null canonical resource. That
    -- is what makes M3's authority binding safe to enable: without it,
    -- resource_uri arrives None and every request deny-closes with
    -- authority_resource_unbound.
    surface = {
      platform_id = surface and surface.platform_id or nil,
      environment = surface and surface.environment or nil,
      canonical_resource_uri = surface and surface.canonical_resource_uri or nil,
    },
    action = {
      action_key = action.action_key,
      action_version = action.action_version,
      tool_name = action.tool_name,
      mapping_id = action.mapping_id,
      mapping_revision = action.mapping_revision,
      risk_class = action.risk_class,
      required_scopes = action.required_scopes,
    },
    request = {
      transport = "mcp_streamable_http",
      http_method = method,
      path = decision_path,
    },
    execution = execution,
    presented_authorization = kong.request.get_header("Authorization"),
  }, {
    -- A9-02: response-signature verification context. The decision is
    -- verified WHEN SIGNED against the published decision key series and the
    -- bindings this gateway can vouch for — the SIGNED bundle's surface and
    -- the matched action, never anything taken from the response itself. An
    -- absent signature is read as before (the authority activates signing by
    -- rollout) UNLESS the operator has declared signing live on this gateway;
    -- a present one that fails ANY check refuses the response, which the
    -- outcome contract below deny-closes.
    crypto = crypto,
    json = { null = channel.null, array_mt = channel.array_mt },
    keys = slot.decision_keys,
    -- The operator's statement that this surface's decisions are signed now.
    -- Read straight from config on every request rather than captured at
    -- configure() time, so flipping it takes effect with a config reload and
    -- not a restart. OFF leaves the rollout posture exactly as it was.
    require_signed = conf.require_signed_decisions or execution_digest ~= nil,
    expected = {
      platform_id = surface and surface.platform_id or nil,
      environment = surface and surface.environment or nil,
      canonical_resource_uri = surface and surface.canonical_resource_uri or nil,
      action_key = action.action_key,
      bundle_version = b.bundle_version,
      execution_request_digest = execution_digest,
    },
  })
  observe_decision_once(slot)

  if outcome == "deny" then
    return deny(403, "ENFORCE_DECISION_DENY",
      "The live decision for this action is deny.", decision_id)
  end
  if outcome ~= "allow" then
    -- on_timeout=deny / on_error=deny: not safely decided is never allow.
    kong.log.warn("mudraid-enforce: /decide not safely decided (",
      detail and detail.reason or "unknown", "); denying closed")
    return deny(503, "ENFORCE_DECIDE_UNAVAILABLE",
      "The action could not be safely decided; protected requests fail closed.", decision_id)
  end

  -- forward: once (A03-13) — disable Kong's automatic upstream retries so
  -- a timeout after forwarding stays "execution unknown" instead of a
  -- silently duplicated consequence. set_retries exists on Kong >= 3.4.
  --
  -- AUDIT-006 M4 item 2: this used to log a warning and forward ANYWAY when
  -- the PDK call was unavailable — an accurate label on an unmitigated
  -- weakness. Kong's service default is retries: 5, so forwarding after a
  -- failed set_retries can replay an ALLOWed protected action up to five
  -- times: exactly the duplicated side effect the audit calls out. The bundle
  -- this plugin just verified declares forward="once" and
  -- retry_forwarded_request=false, and bundle.lua REFUSES any bundle that
  -- says otherwise; forwarding while unable to honour that contract would
  -- make the refusal meaningless. Not being able to guarantee once is "not
  -- safely forwarded", which is deny-closed like every other such state.
  --
  -- The declarative service definition for a protected upstream must ALSO set
  -- retries: 0 (belt and braces) — the governed reference registration pins
  -- that value, and kong/tests/test_mudraid_enforce_contract.py asserts any
  -- declared protected upstream carries it.
  local ok_r = pcall(function() kong.service.set_retries(0) end)
  if not ok_r then
    kong.log.err("mudraid-enforce: kong.service.set_retries unavailable; ",
      "cannot guarantee forward-once, denying closed")
    return deny(503, "ENFORCE_FORWARD_ONCE_UNAVAILABLE",
      "The protected action could not be forwarded exactly once; it was not executed.",
      decision_id)
  end

  -- Trusted context, injected only AFTER enforcement over the trusted hop
  -- (client-supplied same-name headers were stripped above). A signed
  -- context envelope for upstreams that cannot rely on hop trust is a
  -- doc 03 §19 follow-up, not claimed here.
  kong.service.request.set_header("X-MudraID-Decision-Id", decision_id)
  kong.service.request.set_header("X-MudraID-Bundle-Version", tostring(b.bundle_version))
  kong.service.request.set_header("X-MudraID-Action-Key", action.action_key)
end

return MudraidEnforce
