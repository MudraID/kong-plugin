# mudraid-enforce — MudraID enforcement point for Kong

Deny-closed authorization for AI agent traffic, enforced at the gateway.

The plugin polls a signed policy bundle over MudraID's public adapter channel,
verifies it before trusting it, and requires a live decision before any
protected request reaches your upstream.

```
                       ┌──────────────────────────┐
   agent request  ───▶ │  Kong + mudraid-enforce  │ ───▶  your upstream
                       └───────────┬──────────────┘        (only on allow)
                                   │
                                   ▼
                       MudraID adapter channel
                       bundle · decide · keys
```

---

## Install

**Not yet on luarocks.org.** Until the first upload lands, install from the
rockspec in this repository — `luarocks install mudraid-enforce` will not
resolve, and saying otherwise here would be a command that fails on the first
thing a customer types.

```sh
git clone https://github.com/MudraID/kong-plugin.git
cd kong-plugin
luarocks make mudraid-enforce-1.1.0-1.rockspec
```

`luarocks build` accepts the rockspec by URL too, if you would rather not clone:

```sh
luarocks build https://raw.githubusercontent.com/MudraID/kong-plugin/v1.1.0/mudraid-enforce-1.1.0-1.rockspec
```

Then load it into Kong. The plugin name is `mudraid-enforce`:

```sh
# kong.conf
plugins = bundled,mudraid-enforce
```

Or as an environment variable:

```sh
KONG_PLUGINS=bundled,mudraid-enforce
```

Kong must be restarted (not reloaded) the first time a new plugin is added to
`plugins`.

**Installing from source instead:**

```sh
luarocks make mudraid-enforce-1.1.0-1.rockspec
```

## Configure

**The whole customer configuration is two values.**

```yaml
plugins:
  - name: mudraid-enforce
    config:
      base_url: https://api.mudraid.ai
      adapter_token: "{vault://env/MUDRAID_ADAPTER_TOKEN}"
      bundle_signing_secret: "{vault://env/MUDRAID_BUNDLE_SIGNING_SECRET}"
      protected_paths:
        - /mcp
```

Every endpoint is derived from `base_url`; the server derives your tenant,
environment and surface from `adapter_token`. You name no platform id and hold
no secret of ours. Changing environment is one value, never a different build.

This is deliberately the same shape the Python middleware takes —
`HttpDecideClient(base_url=..., adapter_token=...)` — so the two adapters are
one integration model rather than two.

Both secrets are `referenceable`: use Kong's `{vault://...}` syntax so your
declarative config carries a reference and never the material.

### Getting an adapter token

```
POST /api/v1/platforms/{platform_id}/enforcement/adapters
```

The token is shown **once**. It is scoped to one adapter instance — mint a
separate one per gateway rather than sharing.

### Configuration reference

| Field | Default | What it does |
| --- | --- | --- |
| `base_url` | — | MudraID origin for this environment. Every endpoint derives from it. |
| `adapter_token` | — | This instance's bearer. Without it no bundle loads and protected paths fail **closed** (503). |
| `bundle_signing_secret` | — | HMAC-SHA256 verification secret. Without it every bundle is refused — unsigned trust is never an option. |
| `protected_paths` | `[]` | Request paths this plugin enforces on. **Empty means the plugin is inert** and all traffic passes through untouched. |
| `public_methods` | `initialize`, `ping`, `tools/list` | JSON-RPC methods on a protected surface that are control-plane rather than protected actions. |
| `surface_platform_id` | — | The surface this instance speaks for. Required once a second instance exists on the same gateway. |
| `poll_interval_seconds` | `30` | Bundle poll cadence (5–3600). |
| `channel_timeout_ms` | `5000` | Adapter channel timeout (100–60000). |
| `decide_timeout_ms` | `2000` | Decision timeout (100–60000). A timeout is a **denial**. |
| `request_body_max_bytes` | `131072` | Protected requests larger than this are denied, never partially evaluated. |
| `ack_spool_max` | `256` | Bounded, best-effort acknowledgement spool. |

`base_url`, `channel_url`, `decide_url` and `keys_url` overrides exist for
MudraID-operated deployments reaching a service over a private address, and for
tests pointing at a loopback stub. Each **replaces one derived URL** and is
validated exactly as strictly. Supplying one changes where a request goes,
never how carefully it is checked.

### Path matching is not a lexical prefix

`protected_paths` matches an **exact path plus `/`-separated descendants**.

| Configured | Matches | Does **not** match |
| --- | --- | --- |
| `/mcp` | `/mcp`, `/mcp/`, `/mcp/tools` | `/mcpfoo`, `/mcp-evil` |

Every spelling of the request path is tested, so an encoded or dot-segmented
request cannot slip past.

## Multiple tenants on one gateway

Several instances can run on one Kong, one per tenant route, each with its own
adapter credential. Each polls its own bundle on its own clock and resolves its
own bundle by key **with no fallback**.

`surface_platform_id` is the key. A single-instance gateway that declares
nothing keeps working; the moment a second instance is configured, an undeclared
surface is unresolvable and fails **closed** rather than being guessed at.

The field carries no authority. It selects which signed bundle answers, and is
then checked against the server's own attribution of the credential — a
mismatch refuses the bundle rather than trusting the field.

## What this plugin does, and does not, do

Stated plainly, because the difference is usually what matters:

- **Deny-closed.** A decision that cannot be obtained, verified, or read within
  its freshness window is a denial, never an allow. Timeout, error, unmapped
  action, no bundle — all deny.
- **Inert by default.** With no `protected_paths` configured, every request
  passes through untouched. That is by design, not a bypass. Setting the field
  is what designates a surface; nothing else does.
- **Client headers are stripped first.** A reserved set of `x-mudraid-*` request
  headers is removed before anything else runs, so a client cannot forge what
  the gateway asserts downstream. Trusted context is injected only **after** an
  allow.
- **Bundles are verified before they are trusted.** Signature and digests are
  checked on every served bundle. On any refusal the last valid bundle is kept
  rather than falling back to none.
- **Forwarded once.** Upstream retries are disabled on protected requests.
- **It does not sign decision responses** in this release, and does not claim
  to. Do not build a trust assumption on a signature that is not there.
- **Bundle state is per nginx worker.** Every worker polls and validates
  independently. During a rollout, workers may briefly run adjacent bundle
  versions — bounded by one poll interval. A single request never mixes two
  versions. This window is reported honestly rather than hidden.
- **It reports facts, not verdicts about itself.** Nothing here claims
  "enforced" or "verified"; it acknowledges received / validated / active /
  observed and lets the control plane speak.

## Running the tests

The Lua suites need no gateway:

```sh
lua tests/lua/test_endpoints.lua
lua tests/lua/test_mudraid_enforce.lua
lua tests/lua/test_conformance.lua
```

`tests/lua/test_conformance.lua` runs `tests/fixtures/adapter-conformance.json`
— the same corpus the Python adapter is checked against. Two suites written
separately cannot establish that both adapters enforce the same contract; one
shared corpus can.

RS256 bundle verification needs OpenSSL bound into the running process. Bare
`luajit` does not link libcrypto, so run that path under `resty`:

```sh
resty tests/lua/check_rsa_capability.lua
```

## Requirements

- Kong 3.x (provides `resty.http`, `resty.sha256`, `resty.openssl.*`,
  `cjson.safe`)
- Lua 5.1 / LuaJIT

`resty.openssl.pkey` is loaded under `pcall`: its absence degrades RS256 bundle
verification specifically, rather than failing the plugin at load.

## Security

Report privately to **security@mudraid.ai** — see [SECURITY.md](SECURITY.md).
A request reaching your upstream without a verified allow is the class of report
we most want.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
