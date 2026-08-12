-- mudraid-enforce: plugin configuration schema (EP-110-US-04).
--
-- Config carries CONNECTIVITY and BOUNDS only. Everything with authority —
-- which tool names map to which canonical actions, failure modes, the
-- header strip list — comes exclusively from the SIGNED bundle served by
-- the platform-integration adapter channel; none of it is configurable
-- here, so "a second decision policy hidden in plugin configuration"
-- (doc 03 §7) cannot exist.
--
-- Secrets (adapter_token, bundle_signing_secret) are `referenceable`: the
-- declarative config carries {vault://env/...} references resolved from the
-- task environment at runtime — no secret material in kong.yml or the AWS
-- template.

local typedefs = require "kong.db.schema.typedefs"
local path_mod = require "kong.plugins.mudraid-enforce.path"

-- Reject a protected-path prefix whose meaning depends on normalization, at
-- CONFIG LOAD rather than at request time (AUDIT-008 P1-3, "fail startup for
-- ambiguous configuration").
--
-- The surface a plugin instance protects is the single most consequential thing
-- in this config: get it wrong and either a protected action is not evaluated or
-- an unrelated route is. `/mcp/../admin` and `/%6dcp` both have an obvious
-- reading and a defensible different one, so neither is accepted — the operator
-- is asked to write the path they mean. See path.normalize_prefix for the full
-- rule and for why a REQUEST path is treated with the opposite generosity.
local function validate_protected_path(value)
  local normalized, err = path_mod.normalize_prefix(value)
  if not normalized then
    return nil, "protected_paths entry " .. string.format("%q", tostring(value))
      .. " " .. err
  end
  return true
end

return {
  name = "mudraid-enforce",
  fields = {
    -- Enforcement wraps proxied HTTP(S) traffic only.
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- ── THE WHOLE CUSTOMER CONFIGURATION IS TWO VALUES ────────────────
          --
          --     base_url       the MudraID origin for this environment
          --     adapter_token  this adapter instance's bearer
          --
          -- Every endpoint is derived from the first (endpoints.lua), and the
          -- server derives tenant, environment and surface from the second. A
          -- customer names no platform id, holds no shared secret, and selects
          -- an environment by changing ONE value — never a different build.
          --
          -- This is the same shape the Python middleware takes, deliberately:
          -- `HttpDecideClient(base_url=..., adapter_token=...)`. The two
          -- customer-installable adapters previously wanted different things —
          -- this one wanted MudraID's own workload secret — which meant
          -- shipping them together shipped two trust models.
          { base_url = typedefs.url { required = false } },
          -- ── Advanced overrides. NOT the customer setup. ───────────────────
          -- For MudraID-operated deployments reaching a service over a private
          -- address, and for tests pointing at a loopback stub. Each REPLACES
          -- one derived URL and is validated exactly as strictly; supplying one
          -- changes where a request goes, never how carefully it is checked.
          --
          -- `channel_url` keeps its internal default so an EXISTING
          -- MudraID-operated gateway keeps working across this change. A
          -- customer sets base_url and never sees it.
          { channel_url = typedefs.url {
              required = true,
              default = "http://platform-integration-service:8009",
          } },
          { keys_url = typedefs.url { required = false } },
          -- The enforcement surface (platform id) THIS instance speaks for.
          --
          -- Multi-tenant step 3: several instances of this plugin can be
          -- configured on one gateway, one per tenant route, each with its own
          -- adapter credential. This is the key their bundles are held under
          -- and selected by — see tenants.lua for the selection rule.
          --
          -- Not `required`, and deliberately so: a single-instance gateway that
          -- declares nothing keeps working exactly as before. That
          -- compatibility slot is admitted ONLY while it is the sole instance;
          -- the moment a second one is configured an undeclared surface is
          -- unresolvable and fails CLOSED rather than being guessed at.
          --
          -- It carries no authority. It selects which signed bundle answers,
          -- and is then checked AGAINST the server's own attribution of the
          -- credential — a mismatch refuses the bundle rather than trusting
          -- this field.
          { surface_platform_id = { type = "string", required = false } },
          -- Per-adapter bearer token minted by
          -- POST /api/v1/platforms/{id}/enforcement/adapters (shown once).
          -- Optional so an unconfigured gateway still boots: with no token
          -- no bundle can load, and protected paths fail CLOSED (503).
          { adapter_token = { type = "string", required = false, referenceable = true } },
          -- HMAC-SHA256 verification secret — the control plane's
          -- ADAPTER_BUNDLE_SIGNING_SECRET counterpart. Without it every
          -- bundle is refused (unsigned trust is never an option).
          { bundle_signing_secret = { type = "string", required = false, referenceable = true } },
          { poll_interval_seconds = { type = "number", default = 30, between = { 5, 3600 } } },
          { channel_timeout_ms = { type = "integer", default = 5000, between = { 100, 60000 } } },
          -- Enforcement /decide endpoint (EP-220-owned; envelope is
          -- PROVISIONAL — see decide.lua). Absence = deny with typed
          -- reason; there is deliberately no stub/bypass flag.
          { decide_url = typedefs.url { required = false } },
          -- Service credential presented to the private, authenticated
          -- /decide route (doc 08 A08-06: "private authenticated route";
          -- §23: private runtime routes require workload identity). Mirrors
          -- the enforcement-service ENFORCEMENT_SERVICE_SECRET; sent as the
          -- X-Service-Secret header (the same internal S2S profile as
          -- X-Internal-Sync-Secret across the services). `referenceable` so
          -- the declarative config carries only a {vault://env/...} reference,
          -- never secret material. Deny-closed: with decide_url set but this
          -- unset, decide.lua refuses to call unauthenticated (typed error ->
          -- deny), it never falls back to an anonymous request.
          { decide_service_secret = { type = "string", required = false, referenceable = true } },
          { decide_timeout_ms = { type = "integer", default = 2000, between = { 100, 60000 } } },
          -- Bundled-surface designation: request paths (prefix match) this
          -- plugin enforces on. Empty (the default) means NO surface is
          -- designated and every request passes through untouched — the
          -- plugin only ever acts on declared bundled surfaces.
          -- Matching is EXACT PATH PLUS "/"-SEPARATED DESCENDANTS, not a lexical
          -- prefix: `/mcp` covers `/mcp`, `/mcp/` and `/mcp/tools` and does NOT
          -- cover `/mcpfoo` or `/mcp-evil` (path.matches_prefix). Every spelling
          -- of the request path is tested against it (path.candidates), so an
          -- encoded or dot-segmented request cannot slip past.
          { protected_paths = {
              type = "array",
              elements = {
                type = "string",
                match = "^/",
                custom_validator = validate_protected_path,
              },
              default = {},
          } },
          -- JSON-RPC methods on a protected surface that are control-plane
          -- (not protected actions) and pass through: A03-07 classifies
          -- initialization/discovery/ping separately. Anything not listed
          -- and not tools/call (and not a notifications/* message) denies.
          { public_methods = {
              type = "array",
              elements = { type = "string" },
              default = { "initialize", "ping", "tools/list" },
          } },
          -- Bounded framing (A03-07): protected requests larger than this
          -- are denied, never partially evaluated.
          { request_body_max_bytes = { type = "integer", default = 131072, between = { 1024, 10485760 } } },
          -- Bounded best-effort ack spool (see ack.lua for the honest
          -- durability limitation).
          { ack_spool_max = { type = "integer", default = 256, between = { 8, 8192 } } },

          -- ---------------------------------------------------------------
          -- Signed containment projection (doc 05 A05-06/A05-07)
          -- ---------------------------------------------------------------
          --
          -- OFF BY DEFAULT, and the default is a CONTRACTED state, not a
          -- loophole. With containment_feed_url unset this adapter is outside
          -- the V2 containment feed: A05-07 names that case explicitly —
          -- "legacy/offline consumers without the V2 feed retain token/cache
          -- exposure and cannot be included in a stronger fleet claim" — so
          -- the adapter says so once, in the log, and behaves exactly as it did
          -- before. It never quietly implies a containment guarantee it has no
          -- feed for.
          --
          -- The moment the url IS set, the surface is deny-closed on
          -- containment: every protected action requires a verified projection
          -- that is inside containment_max_staleness_seconds, and a missing,
          -- unverifiable or stale-beyond-maximum projection denies (503) rather
          -- than allowing. Mirrors the server's own posture: enforcement-service
          -- publishes nothing at all until CONTAINMENT_FEED_SIGNING_SECRET is
          -- provisioned, and 503s if asked to.
          { containment_feed_url = typedefs.url { required = false } },
          -- POST /api/v2/containment/convergence/acknowledgements. Separate
          -- from the feed url because acknowledgement is a separate right: an
          -- adapter that reads the feed but cannot acknowledge is still
          -- contained correctly, it merely cannot be COUNTED as converged
          -- (A05-07), and that difference should be configurable as such.
          { containment_ack_url = typedefs.url { required = false } },
          -- The credential this gateway presents on BOTH containment calls
          -- (X-Service-Secret), and the only thing that tells the server which
          -- surface it is. It is deliberately NOT decide_service_secret: that
          -- secret is one workload credential shared by every gateway and
          -- therefore names no tenant, so scoping a containment projection by it
          -- would let any holder read any tenant's — the exact set of agents,
          -- actions and resources that tenant has contained, and why. An operator
          -- mints this credential for exactly one (organization, environment,
          -- adapter id) with the server's
          -- CONTAINMENT_ADAPTER_CREDENTIAL_SECRET; the server verifies it and
          -- derives the stream FROM it, so this gateway cannot name another
          -- tenant's surface even if it wanted to. Unset means both containment
          -- calls are not made at all (never anonymous), which reaches the hot
          -- path as "no verified projection" and denies.
          { containment_adapter_credential = {
              type = "string", required = false, referenceable = true } },
          -- HMAC-SHA256 verification secret for the feed — enforcement-service's
          -- CONTAINMENT_FEED_SIGNING_SECRET counterpart. Without it every
          -- record is refused (CONTAINMENT_SIGNING_SECRET_UNCONFIGURED);
          -- unsigned trust is never an option.
          { containment_feed_signing_secret = {
              type = "string", required = false, referenceable = true } },
          -- Expected signing key id. Optional: unset means the HMAC is the only
          -- check (any key id whose digest verifies is accepted). Set, it PINS
          -- the key, and a record naming another key is refused as a rotation
          -- whose material never reached this gateway — a misconfiguration that
          -- cannot clear on its own, which is why it is its own typed refusal.
          { containment_feed_signing_key_id = { type = "string", required = false } },
          -- HMAC-SHA256 signing secret for acknowledgements —
          -- enforcement-service's CONTAINMENT_ACK_INGEST_SECRET counterpart.
          -- Without it no acknowledgement is sent at all (an unsigned ack is
          -- refused server-side and would only forge a convergence claim here).
          { containment_ack_signing_secret = {
              type = "string", required = false, referenceable = true } },
          { containment_ack_signing_key_id = {
              type = "string", required = false, default = "containment-ack-v1" } },
          -- The adapter id this gateway acknowledges as. It is the DENOMINATOR
          -- entry in a convergence measurement (GET /convergence?required=...),
          -- so it must be the id the operator declared as required — an
          -- adapter acknowledging under an unexpected id converges nothing.
          { containment_adapter_id = { type = "string", required = false } },
          -- A05-06: the maximum age of the last projection a disconnected
          -- adapter may keep using. Past it, affected protected actions deny.
          -- Bounded well below a day: a "maximum staleness" an operator can set
          -- to a week is not a containment bound.
          { containment_max_staleness_seconds = {
              type = "number", default = 300, between = { 5, 86400 } } },
          -- Poll cadence for the feed. Independent of the bundle poll: a
          -- containment projection is the artifact with a freshness deadline,
          -- and tying it to the bundle's 30s default would make one number
          -- govern two unrelated bounds.
          { containment_poll_interval_seconds = {
              type = "number", default = 15, between = { 5, 3600 } } },
          -- Tolerated clock disagreement between this gateway and the feed
          -- publisher. A projection issued further into our future than this is
          -- treated as unusable, not as maximally fresh.
          { containment_clock_skew_seconds = {
              type = "number", default = 60, between = { 0, 3600 } } },
        },
      },
    },
  },
}
