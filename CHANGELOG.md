# Changelog

All notable changes to `mudraid-enforce` are recorded here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version here is `MudraidEnforce.VERSION` in `plugins/mudraid-enforce/handler.lua`,
which is also the version the plugin reports to the control plane on every
acknowledgement — `scripts/check_kong_plugin_package.py` holds the two equal so a
gateway can never report a version that was never packaged.

## [1.1.0] — unreleased

First packaged release. Earlier versions existed in MudraID's monorepo and were
deployed only to MudraID-operated gateways; this is the first version installable
by anyone else, so the entries below describe the change **from that internal
shape to a customer-installable one** rather than from a prior public release.

### Changed — this is the breaking one

- **The plugin now speaks the public adapter channel.** It previously called
  `/api/v1/internal/enforcement/*` and authenticated with
  `decide_service_secret` — MudraID's own workload credential — presented as
  `X-Service-Secret`.

  That was not a configuration difference, it was a **different trust model**. A
  customer holding that secret holds the credential every MudraID gateway
  shares; it names no tenant, so it cannot be scoped to them, and it
  authenticates callers to a private route as us. The plugin and the Python
  middleware could not have shipped together without shipping two integration
  models, one of which required our internal secret.

  All five endpoints now derive from one `base_url` and authenticate with one
  per-adapter bearer:

  ```
  bundle     GET  {base}/api/v1/adapter/enforcement/bundle
  decide     POST {base}/api/v1/adapter/enforcement/decide
  keys       GET  {base}/api/v1/adapter/enforcement/keys
  heartbeat  POST {base}/api/v1/adapter/enforcement/heartbeat
  acks       POST {base}/api/v1/adapter/enforcement/acknowledgements
  ```

  `plugins/mudraid-enforce/endpoints.lua` is the single derivation, and
  `tests/lua/test_endpoints.lua` proves it agrees with the Python middleware by
  **reading that package's constants out of its source** rather than restating
  them — a test asserting a literal it also declares proves only that a file is
  self-consistent.

- **HMAC is no longer required to accept a bundle.** A bundle carrying a valid
  RS256 signature is accepted on that evidence alone. When an HMAC secret is
  configured it is still checked, and a present-but-invalid signature of either
  kind is always a refusal. What changed is that the absence of a shared secret
  is no longer itself a refusal — asymmetric verification is strictly better,
  because anyone who can verify with HMAC can also sign with it.

### Added

- `base_url` — the one value every endpoint derives from.
- `keys_url` — optional override for the public-key endpoint, validated exactly
  as strictly as the derived URL it replaces.
- A LuaRocks manifest (`mudraid-enforce-1.1.0-1.rockspec`). Before it,
  "installing" meant copying a directory and hoping; a file left out surfaced as
  a `require` failure during a gateway reload, in production, on the first
  protected request.
- This changelog, and a README that documents the two-value configuration, the
  path-matching rule, the multi-tenant selection rule, and what the plugin does
  **not** do.

### Security

- `endpoints.bearer` deliberately does **not** fall back to any other configured
  secret. An adapter with no token makes no call at all, which reaches the hot
  path as a refusal rather than as an anonymous request some route might answer.
- `tests/lua/test_endpoints.lua` asserts across the **whole plugin** — not only
  the files that were fixed — that no customer-facing module reaches for an
  internal path, presents `X-Service-Secret`, or reads `decide_service_secret`.
  A future module added by someone who copied an older one is exactly how this
  comes back.

  `channel.lua` is the one file that still uses `X-Service-Secret`, and the
  assertion is positional rather than absent: the signed **containment** feed is
  a separate channel owned by enforcement-service with its own
  per-(org, environment, adapter) credential, and every occurrence must fall
  after that section begins. Exempting the file outright would have let the
  adapter channel regain the secret silently.

### Packaging

- The public snapshot now contains the plugin, its Lua tests, its fixtures, its
  licence, its disclosure path and its manifest — and nothing else. `aws/`, the
  `Dockerfile`, `kong.yml` and the three Python suites that assert on them are
  MudraID's own deployment material, not a customer artifact.

  This was found rather than assumed: shipping a `Dockerfile` that `COPY`s from
  an excluded `aws/` produced a public tree that could not build, and the
  snapshot scanner passed it because it checks for leaked identifiers and never
  asked whether the thing builds.

### Known limitations

Stated here rather than discovered:

- **Decision responses are not signed** in this release, and the plugin does not
  claim they are.
- **Bundle state is per nginx worker.** During a rollout, workers may briefly
  run adjacent bundle versions, bounded by one poll interval. A single request
  never mixes two versions.
- **Acknowledgements are best-effort** and spooled within a bounded buffer
  (`ack_spool_max`). They are reports, not a delivery guarantee.
