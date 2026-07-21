# Operational monitoring

These are the on-box operator tools for the io_uring fuzzing campaign. They are
deployed to `/usr/local/bin` and `/etc/systemd/system` (durable across reboot).
They are **operational glue**, not part of the fail-closed control plane: they
observe state and send one-way alerts. None of them can promote, approve, or
write an AFL queue.

| file | installed as | purpose |
|---|---|---|
| `iou-status` | `/usr/local/bin/iou-status` | one-shot dashboard: fleet, crashes, AI lane, promoted seeds, budget. Run `sudo iou-status`. |
| `iou-alert` | `/usr/local/bin/iou-alert` | best-effort one-way alert (journal + `/var/log/iou-alert.log` always; Telegram direct via `api.telegram.org` when a bot token is present). Never fails its caller. |
| `iou-crashwatch` | `/usr/local/bin/iou-crashwatch` | 10-min watcher. Pages on: GOLD kernel memory-safety bug (deduped by root cause), non-gold crash, fleet degradation (<10 workers, two checks), and SUSTAINED AI-lane failure (no planner success in 6h / budget cap / kill switch). |
| `iou-crashwatch.service` / `.timer` | `/etc/systemd/system/` | runs `iou-crashwatch` every 10 minutes. |

## Alert channels, most-reliable first
1. journal + `/var/log/iou-alert.log` and, for crashes, `~saedyn/CRASH_FOUND.txt`
   (always works, no credentials)
2. Telegram **direct** to `api.telegram.org` — enabled only if
   `/etc/iou-ai/credentials/telegram-bot.token` + `telegram-chat.id` exist.
   This deliberately does NOT use the Cloudflare relay (that path is for two-way
   approvals; its flaky outbound push is why alerts go direct).

## Grading — what counts as "gold"
GOLD (page immediately): use-after-free, slab/global/stack-out-of-bounds,
double/invalid-free, general protection fault, refcount_t, `kernel BUG at`, any
KASAN report. SILVER (notified, not urgent): bare panic, `WARNING: at`, null
deref. UNGRADED (no readable kernel log): still pages — fail loud, because a
missed 0-day costs far more than a false alarm.

## Kill switches
- `sudo touch /var/lib/iou-ai/runtime/AI_CALLS_DISABLED` — stops paid AI + the
  auto-promote lane.
- `sudo touch /var/lib/iou-ai/runtime/AUTO_PROMOTE_DISABLED` — stops auto-promote
  only; the shadow planner keeps running.
