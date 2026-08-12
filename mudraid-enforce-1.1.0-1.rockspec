-- LuaRocks manifest for the MudraID Kong enforcement plugin.
--
-- WHY THIS FILE EXISTS
-- ====================
-- Until this existed, "installing" the plugin meant copying a directory and
-- hoping. There was no manifest, so nothing declared which Lua modules make up
-- the plugin, which runtime libraries it needs, or what version any of it is.
-- A file left out of a copy fails at the first `require` — during a gateway
-- reload, in production, on a path nobody exercises until a protected request
-- arrives.
--
-- `modules` below is therefore the package, not a description of it: LuaRocks
-- installs exactly these files and nothing else, so a module missing here is a
-- module missing from every install.
-- scripts/check_kong_plugin_package.py holds this list equal to the directory
-- and to every internal `require`, because a manifest that drifts from the
-- tree is worse than none — it reads as authoritative.
--
-- VERSION. The `1.1.0` half is the plugin's version and must equal
-- `MudraidEnforce.VERSION` in handler.lua, which is the value reported to the
-- control plane on every acknowledgement. The `-1` is the rockspec revision,
-- a LuaRocks convention for repackaging the same source; it bumps when this
-- file changes and the plugin does not.

package = "mudraid-enforce"
version = "1.1.0-1"

source = {
   url = "git+https://github.com/MudraID/kong-plugin.git",
   tag = "v1.1.0",
}

description = {
   summary = "MudraID enforcement point for Kong — deny-closed authorization for AI agent traffic.",
   detailed = [[
Kong plugin that enforces MudraID authorization decisions on designated
request surfaces. It polls a signed policy bundle over the public adapter
channel, verifies it before trusting it, and requires a live decision before
any protected request reaches the upstream.

Deny-closed: a decision that cannot be obtained, verified, or read within its
freshness window is a denial, never an allow. With no protected paths
configured the plugin is inert and passes all traffic through untouched.

Configuration is two values — `base_url` and `adapter_token` — from which
every endpoint is derived and the tenant, environment and surface are
resolved server-side.
   ]],
   homepage = "https://github.com/MudraID/kong-plugin",
   license = "Apache-2.0",
}

dependencies = {
   "lua >= 5.1",
   -- Kong itself is NOT declared as a dependency, and the omission is
   -- deliberate rather than an oversight. This plugin is installed INTO an
   -- existing Kong, whose own package provides `kong.db.schema.typedefs`,
   -- `resty.http`, `resty.sha256` and `resty.openssl.*`. Declaring Kong here
   -- would make LuaRocks try to resolve and install a gateway alongside the
   -- plugin meant to extend it.
   --
   -- The runtime libraries this plugin requires, all supplied by Kong:
   --   cjson.safe               JSON that returns nil instead of raising
   --   kong.db.schema.typedefs  schema field types
   --   resty.http               the adapter channel and /decide transport
   --   resty.sha256             bundle digest verification
   --   resty.openssl.hmac       bundle HMAC verification
   --   resty.openssl.pkey       RS256 bundle verification (loaded under pcall;
   --                            absence degrades that one path, see crypto.lua)
}

build = {
   type = "builtin",
   modules = {
      ["kong.plugins.mudraid-enforce.ack"] = "plugins/mudraid-enforce/ack.lua",
      ["kong.plugins.mudraid-enforce.base64"] = "plugins/mudraid-enforce/base64.lua",
      ["kong.plugins.mudraid-enforce.bundle"] = "plugins/mudraid-enforce/bundle.lua",
      ["kong.plugins.mudraid-enforce.canonical"] = "plugins/mudraid-enforce/canonical.lua",
      ["kong.plugins.mudraid-enforce.channel"] = "plugins/mudraid-enforce/channel.lua",
      ["kong.plugins.mudraid-enforce.compare"] = "plugins/mudraid-enforce/compare.lua",
      ["kong.plugins.mudraid-enforce.containment"] = "plugins/mudraid-enforce/containment.lua",
      ["kong.plugins.mudraid-enforce.crypto"] = "plugins/mudraid-enforce/crypto.lua",
      ["kong.plugins.mudraid-enforce.decide"] = "plugins/mudraid-enforce/decide.lua",
      ["kong.plugins.mudraid-enforce.endpoints"] = "plugins/mudraid-enforce/endpoints.lua",
      ["kong.plugins.mudraid-enforce.handler"] = "plugins/mudraid-enforce/handler.lua",
      ["kong.plugins.mudraid-enforce.headers"] = "plugins/mudraid-enforce/headers.lua",
      ["kong.plugins.mudraid-enforce.matcher"] = "plugins/mudraid-enforce/matcher.lua",
      ["kong.plugins.mudraid-enforce.path"] = "plugins/mudraid-enforce/path.lua",
      ["kong.plugins.mudraid-enforce.receipt"] = "plugins/mudraid-enforce/receipt.lua",
      ["kong.plugins.mudraid-enforce.schema"] = "plugins/mudraid-enforce/schema.lua",
      ["kong.plugins.mudraid-enforce.tenants"] = "plugins/mudraid-enforce/tenants.lua",
   },
}
