-- mudraid-enforce: acknowledgement spool (EP-110-US-04, doc 03 A03-12/14).
--
-- Best-effort, BOUNDED, in-memory spool of adapter acknowledgement reports
-- (bundle received/validated/active facts, validation errors, first
-- observed decision) destined for the platform-integration adapter channel
-- POST /api/v1/internal/enforcement/acknowledgements.
--
-- HONEST LIMITATION (stated per A03-12): an in-memory queue is NOT durable
-- acceptance. A worker crash or restart loses spooled reports; when the
-- spool overflows, the OLDEST report is dropped and counted. That is
-- acceptable for these reports because they are adapter STATE facts, not
-- decision evidence: the control plane's ladder self-heals on the next
-- successful report, and replay is deduplicated server-side by report_id.
-- Durable evidence spooling (decision/enforcement events) is EP-230/Audit
-- territory and is deliberately NOT claimed here.
--
-- Each report keeps a STABLE report_id across delivery retries so a retried
-- POST is an idempotent replay, never a duplicate row (server contract:
-- ACK_REPLAY_MISMATCH guards content drift).
--
-- Pure Lua — unit-testable outside the gateway.

local _M = {}

function _M.new(max)
  return {
    items = {},
    max = max or 256,
    dropped = 0, -- measured fact, surfaced in logs; never hidden
  }
end

--- Enqueue one report table (must already carry its stable report_id).
-- Oldest-first drop on overflow.
function _M.push(spool, report)
  if #spool.items >= spool.max then
    table.remove(spool.items, 1)
    spool.dropped = spool.dropped + 1
  end
  spool.items[#spool.items + 1] = report
end

--- Attempt delivery in FIFO order via send(report) -> boolean.
-- Stops at the first failure (preserves ordering; the channel merges facts
-- by reported_at, so out-of-order delivery would misstate the ladder).
-- @return number of reports delivered
function _M.drain(spool, send)
  local sent = 0
  while spool.items[1] do
    if not send(spool.items[1]) then
      break
    end
    table.remove(spool.items, 1)
    sent = sent + 1
  end
  return sent
end

function _M.size(spool)
  return #spool.items
end

return _M
