-- mudraid-enforce: the tenant bundle set and the selection rule.
--
-- Step 3 of the multi-tenant delivery order
-- (docs/5 features/outputs 2/m0/DESIGN-2026-08-01-multi-tenant-enforcement.md).
--
-- WHY THIS IS ITS OWN MODULE
-- --------------------------
-- Until now handler.lua held ONE verified bundle in a module-level `state`
-- table and every read of it was unconditional:
--
--     local b = state.bundle
--
-- `state` is module-level, so it is per nginx WORKER, not per plugin instance.
-- Kong already supports several instances of this plugin (one per route, each
-- with its own `conf` and therefore its own adapter credential) — the
-- handler's own `configure()` comment says so. What it did NOT have is
-- somewhere to put more than one bundle, so instance two would have read
-- instance one's.
--
-- That is the whole multi-tenant defect in one line, and it is why the set and
-- its selection rule live here, in a module with NO Kong or ngx dependency:
-- the seven contract specs in kong/tests/lua/test_mudraid_enforce.lua can then
-- be executed against it directly, instead of being asserted about code that
-- only runs inside a gateway.
--
-- THE RULE, STATED ONCE
-- ---------------------
-- **A request is evaluated against the bundle belonging to the surface its own
-- plugin instance declares, or it is denied.** There is no fallback, no
-- "closest match", and no tie-break. Every failure to resolve exactly one
-- bundle is a refusal.
--
-- The fallback is the dangerous case and it is worth naming explicitly,
-- because it is the natural shape of a single-tenant-to-multi-tenant
-- conversion: "if we only have one bundle loaded, use it." Under Option B that
-- hands tenant A's request to tenant B's mappings, and handler.lua then
-- forwards B's signed, authentic, non-empty surface to /decide. Enforcement
-- returns a CORRECT decision about the WRONG tenant's resource, and nothing
-- downstream can detect it because every field it checks is genuine.
--
-- PARTIAL REFRESH (the question step 2 §6.3 left open)
-- ---------------------------------------------------
-- Slots are INDEPENDENT. One tenant's poll failing has no effect on any other
-- tenant's slot, in either direction:
--
--   * T's refresh fails and T has a verified bundle -> T keeps serving on it.
--     This is not a new policy; it is exactly what the single-tenant handler
--     already does on a failed heartbeat, a failed fetch and a refused bundle.
--   * T has never loaded one -> T's surface denies, and U's does NOT.
--   * every poll fails -> N independent instances of today's behaviour.
--
-- The two failure modes a naive design falls into are both excluded by that:
-- "any tenant unhealthy -> deny everything" is a self-inflicted outage, and
-- "any tenant healthy -> serve" is a widening. Keying the lookup, with no
-- fallback, is what avoids both.
--
-- Worth recording honestly: there is NO wall-clock staleness bound anywhere in
-- this plugin. `on_stale_bundle = "deny"` in bundle.lua is a value the signed
-- bundle must DECLARE, not a timer that runs here. So "one tenant is stale
-- while its neighbours are current" is a divergence in ACTION MAPPINGS, never
-- in authority: every protected call still requires a live /decide, so a stale
-- bundle can mis-map an action but cannot grant one. That bounds the blast
-- radius of a partial refresh, and it is the reason this question resolves
-- without new policy.

local _M = {}

-- Refusal reasons. Each is a distinct operator-visible fact, not a generic
-- "denied": the three describe a MISCONFIGURATION, and conflating them with
-- the ordinary "no bundle yet" would hide a wiring error behind a state that
-- looks like a cold start and clears itself.
_M.UNIDENTIFIED = "surface_unidentified"
_M.AMBIGUOUS = "surface_ambiguous"
_M.NO_BUNDLE = "no_valid_bundle"

-- The reserved key for an instance that declares no `surface_platform_id`.
--
-- It exists for compatibility: the single gateway running in staging today has
-- one instance and no declared surface, and making the field required would
-- deny every protected request from the moment this ships until Terraform
-- catches up (step 5). A NUL prefix cannot collide with a platform id, which
-- is a UUID string.
--
-- It is admitted ONLY when it is the sole configured instance. The moment a
-- second instance exists, an undeclared surface is unresolvable — there is no
-- longer an "obviously the only one" to be — so it refuses instead of
-- guessing. That is the compatibility path closing itself the instant it stops
-- being safe, rather than an operator having to remember to close it.
_M.UNBOUND_KEY = "\0unbound"

--- The selection key for one plugin instance, from its config alone.
--
-- Deliberately a pure function of `conf`: selection must never depend on which
-- bundle polled most recently, which is the property spec (b) names.
function _M.key_for(conf)
  local declared = conf and conf.surface_platform_id
  if type(declared) == "string" and declared ~= "" then
    return declared
  end
  return _M.UNBOUND_KEY
end

--- Build the admitted key set from ALL configured instances.
--
-- Called from `configure()`, which Kong invokes on every declarative reload
-- with every instance — the only place the whole picture is visible. Two
-- instances declaring the SAME surface is the ambiguity spec (c) describes:
-- two credentials claiming one tenant is a defect in the deployment, and
-- picking either would be choosing a winner between two things that disagree.
-- Both refuse.
--
-- Slots are deliberately NOT pruned when a tenant leaves the configuration.
-- The plan is what authorises a lookup, so a departed tenant's slot can never
-- be selected again even though its bundle is still in memory — removing it
-- would buy nothing for isolation and would discard a bundle that a reload
-- flapping a tenant out and back in would immediately have to re-fetch. What
-- it costs is bounded memory: one slot per tenant this worker has ever been
-- configured with.
function _M.plan(confs)
  local seen, refusals, admitted = {}, {}, {}
  local n = confs and #confs or 0

  for i = 1, n do
    local key = _M.key_for(confs[i])
    seen[key] = (seen[key] or 0) + 1
  end

  for key, count in pairs(seen) do
    if count > 1 then
      refusals[key] = _M.AMBIGUOUS
    elseif key == _M.UNBOUND_KEY and n > 1 then
      refusals[key] = _M.UNIDENTIFIED
    else
      admitted[key] = true
    end
  end

  return { admitted = admitted, refusals = refusals, instances = n }
end

--- An empty set. Distinct from nil so callers never branch on "is there a set".
function _M.new()
  return { slots = {}, plan = _M.plan({}) }
end

--- The mutable per-tenant slot, created on demand.
--
-- Holds everything that used to be a single field on the handler's module-level
-- `state`: the bundle, the poll clock, the once-only log latches and the
-- first-observed-decision fact. Each of those is a PER-ADAPTER fact — the ack
-- carrying it is posted with that adapter's own credential — so sharing one
-- across tenants would misattribute it, not merely blur it.
function _M.slot(set, key)
  local slot = set.slots[key]
  if not slot then
    slot = {
      key = key,
      bundle = nil,
      attributed_platform_id = nil,
      last_poll = 0,
      decision_observed = false,
      no_bundle_logged = false,
      spool = nil,
    }
    set.slots[key] = slot
  end
  return slot
end

--- Resolve the ONE bundle this instance may enforce with, or a refusal.
--
-- Returns (bundle, nil, key) or (nil, reason, key). Never returns a bundle
-- belonging to any key other than this instance's own — the property that all
-- of spec (b)'s cross-tenant cases reduce to.
function _M.select(set, conf)
  local key = _M.key_for(conf)

  local refusal = set.plan.refusals[key]
  if refusal then
    return nil, refusal, key
  end
  if not set.plan.admitted[key] then
    -- The instance is not in the plan at all: `configure()` has not run, or
    -- ran without this instance. Unresolvable, so it denies. An empty set
    -- reaches here too, which is spec (g) — zero entries deny exactly as nil
    -- does, and for the same reason, rather than reading as "nothing to
    -- enforce".
    return nil, _M.UNIDENTIFIED, key
  end

  local slot = set.slots[key]
  if not slot or not slot.bundle then
    return nil, _M.NO_BUNDLE, key
  end
  return slot.bundle, nil, key
end

--- Step 4's narrowed check: do the three sources of tenant identity agree?
--
-- Step 2 (DESIGN-2026-08-01-multitenant-step2-channel.md §4) established that
-- tenant identity is attested by WHICH CREDENTIAL fetched a bundle, because
-- /heartbeat returns the server's own `platform_id` for that credential. That
-- is a stronger binding than the payload's own claim, which is signed with an
-- HMAC every tenant shares — a valid signature proves the PLATFORM signed a
-- bundle, never that it belongs to the tenant asking (spec (e)).
--
-- So there are three independent statements of who this surface belongs to:
--
--   1. what the deployment DECLARED   (conf.surface_platform_id -> `key`)
--   2. what the server ATTRIBUTED     (heartbeat platform_id, per credential)
--   3. what the payload CLAIMS        (content.surface.platform_id, signed)
--
-- They must agree. Any disagreement means a credential was delivered to the
-- wrong instance or a bundle was compiled for the wrong surface, and both are
-- states where continuing would enforce one tenant's mappings under another's
-- name. This should never fire; it firing is how we find out that it can.
--
-- Credential mis-delivery is specifically what step 2 §5 flagged as "the piece
-- most likely to be underestimated" in a per-tenant-credential design. This
-- turns it from something discovered at request time into a refusal at poll
-- time, acknowledged as a fact on the adapter channel.
--
-- It compares whichever of the three are actually available, rather than
-- demanding all three, because they do not all arrive at the same moment. The
-- handler's bootstrap path deliberately attempts a fetch after a FAILED
-- heartbeat when it holds no bundle at all, so at that instant there is no
-- attribution to compare against — and bundle.lua already refuses any bundle
-- whose content.surface.platform_id is absent or blank, so the payload's claim
-- is always there. Requiring the attribution unconditionally would have turned
-- that resilience path into a permanent refusal.
--
-- A declared surface must therefore be bound by SOMETHING: the attribution
-- when it is available, the payload's claim otherwise. The claim alone is the
-- weaker of the two, and it is accepted only for as long as the stronger one
-- is missing — the next successful heartbeat upgrades the binding and would
-- catch a disagreement then.
--
-- Returns nil when consistent, or a reason string.
function _M.attribution_conflict(key, attributed, claimed)
  local has_attributed = type(attributed) == "string" and attributed ~= ""
  local has_claimed = type(claimed) == "string" and claimed ~= ""

  if key ~= _M.UNBOUND_KEY then
    if has_attributed and key ~= attributed then
      return "declared_surface_mismatch"
    end
    if has_claimed and key ~= claimed then
      return "payload_surface_mismatch"
    end
    if not has_attributed and not has_claimed then
      -- A declared tenant with nothing at all binding a bundle to it. Fail
      -- closed: an identity that cannot be established is not an agreement.
      return "surface_unattributed"
    end
    return nil
  end

  -- Undeclared (the single-instance compatibility slot). There is no declared
  -- surface to check against, but the two REMOTE statements must still agree
  -- with each other — that is what catches a bundle compiled for one surface
  -- being served to a credential the server attributes to another.
  if has_attributed and has_claimed and attributed ~= claimed then
    return "payload_surface_mismatch"
  end
  return nil
end

return _M
