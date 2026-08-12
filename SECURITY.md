# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Report it privately to
**security@mudraid.ai**, and we will acknowledge within **2 business days**.

Please include, as far as you can establish it:

- what an attacker can do — the effect, not only the flaw;
- the version you tested, and how you installed it;
- a reproduction, or the smallest thing that shows the behaviour.

You will get a substantive reply, not only an acknowledgement: what we
reproduced, what we could not, and what we intend to do. If we disagree that
something is a vulnerability we will say so and explain why, rather than letting
the report go quiet.

We will not pursue legal action over good-faith research that stays within your
own accounts and data, does not degrade the service for others, and does not
access or retain anyone else's information.

## What is in scope

This repository — the library's own code and the wiring it documents.

The service it talks to is a separate system with the same contact address, and
a report about one is welcome under the other; we would rather route it
ourselves than have you guess which it belongs to.

## What this plugin does and does not do

Worth stating plainly, because a report is often about the difference:

- It carries a **deny-closed** enforcement model. A decision that cannot be
  obtained, verified, or read within its freshness window is a denial, never an
  allow. **A request reaching the upstream without a verified allow is a
  vulnerability in this plugin**, and is the class of report we most want.
- With no protected paths configured the plugin is **inert** and passes all
  traffic through untouched. That is by design, not a bypass — but a request
  matching a configured protected path that still reaches the upstream
  unchecked is not, and we want to hear about it.
- It **does not sign decision responses** in this release, and does not claim
  to. Do not build a trust assumption on a signature that is not there.
- It holds a credential you supply. It never writes one to disk and never logs
  one; **a credential appearing in any log line is a vulnerability**, and one we
  will treat as such even when nothing else is exploitable.
- It strips a reserved set of request headers so a client cannot forge what the
  gateway asserts downstream. **A reserved header surviving from the client to
  the upstream is a vulnerability.**

## Supported versions

Maturity and support for every released version are declared in the MudraID
adapter support matrix, which is the authority here — not this section, and not
a marketing page. It is not shipped inside this package; ask
security@mudraid.ai for the entry covering the version you tested.

This package is **1.x**. The version is in `CHANGELOG.md` and in the rockspec
filename, and the running plugin reports the same value to the control plane on
every acknowledgement — so `kong.plugins.mudraid-enforce.handler.VERSION` from a
gateway is a fine way to say which you tested.

Report against the latest released version where you can, and say which version
you tested where you cannot.
