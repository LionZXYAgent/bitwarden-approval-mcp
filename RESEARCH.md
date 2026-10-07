# Research: existing human-approval credential gateways for AI agents

Survey done 2026-10-07 while scoping this project. Goal: find anything that
already gives AI agents **per-request, human-approved** access to a Bitwarden
(or other) vault, ideally via **Telegram**, suitable for Alpine / lightweight
deployment. Only projects actually inspected are listed; links are real.

## Closest matches (human-in-the-loop secret access for agents)

| Project | Link | Vault | Per-request human approval | Telegram | Transport | Notes / maintenance |
| --- | --- | --- | --- | --- | --- | --- |
| **Bitwarden Agent Access** | https://github.com/bitwarden/agent-access | Bitwarden (pluggable) | ✅ Yes — user approves each credential | ❌ (approves on the paired device) | Rust CLI/SDK, E2E-encrypted Noise tunnel | Official, **early preview**, active (pushed Oct 2026). **Injects** creds into the child process env — the model never sees them. Strongest security model; no Telegram, no MCP. |
| **1Password for Claude / Agentic Autofill** | https://1password.com/press/2026/july/1password-for-claude · https://www.1password.dev/agentic-autofill | 1Password | ✅ Yes — biometric prompt per task | ❌ (1Password desktop app) | Browser-extension injection | Commercial, 1Password-only. Zero-exposure (fills into page, model never sees secret). Not self-hostable, not Bitwarden. |
| **Secret Gate** | https://github.com/johnuopini/secret-gate | 1Password Connect | ✅ Yes | ✅ **Yes** | Go, MCP (stdio) + skills | Closest in spirit. **1Password only**, needs a 1Password Connect server. MIT, small (13★), active Aug 2026. Can `exec_with_secret` to inject rather than reveal. |
| **op-remote** | https://github.com/wyattjoh/op-remote | 1Password | ✅ Yes (Approve/Reject/Auto-Approve/Stop) | ✅ **Yes** | TypeScript, MCP | 1Password only; resolves `op://` refs at startup. No license file, 0★, Jul 2026. |
| **Agent Vault** | https://github.com/loonshoot/agent_vault | 1Password, env files | ✅ Yes (phone tap) | ❌ (ngrok link / ntfy; Telegram on roadmap) | TypeScript, MCP | Bitwarden listed as *planned*, not implemented. MIT, 1★. |
| **Guarded MCP** | https://github.com/fernandosmither/guarded-mcp | n/a (gates tool actions, not a vault) | ✅ Yes (per tool action) | ✅ **Yes** | Python, MCP | General approval gateway, not credential-specific. Auto-approves reads, prompts on writes. No license, 0★. |
| **Telegram-Bot-MCP (launch-approval gate)** | https://github.com/tr4m0ryp/Telegram-Bot-MCP | n/a (launch approval) | ✅ Yes (mints single-use token) | ✅ **Yes** | Python, FastMCP streamable HTTP + Postgres | Good design reference (inbound tap never reaches the model). Not a vault. MIT, 0★. |

## Bitwarden / Vaultwarden vault MCP servers (no Telegram approval)

| Project | Link | Approval style | Notes |
| --- | --- | --- | --- |
| **Bitwarden MCP server (official)** | https://github.com/bitwarden/mcp-server | None for reads (local-only trust); has **device-approval** tools for org login requests | Node/`npx` + `bw` CLI, **stdio only**, uses `BW_SESSION`. Active (272★). Heavy on Alpine (Node + CLI). Not a per-secret human gate. |
| **Vaultwarden-MCP** (shadowsdistant) | https://mcpservers.org/servers/shadowsdistant/vaultwarden-mcp | Desktop **window** approval per reveal (`VW_MCP_MODEL_REVEAL=ask`) | Uses the `bw` CLI; approval is a local desktop prompt, not remote/phone. GPL-3.0. |
| **vaultgate** | https://glama.ai/mcp/servers/adamrowles1996/vaultgate | OAuth scopes + operator login (TOTP); reveals one field at a time | Remote MCP, its own OAuth 2.1 server; approval is scope-based at connect time, not per-request push. Can also *use* creds without revealing (connectors). Apache-2.0, 2★. |
| **`bw serve`** (Bitwarden CLI) | https://github.com/bitwarden/clients | Vault Management REST API; has `device-approval` endpoints | A local REST wrapper around the vault — no human gate on reads; you'd build the gate yourself on top. Node-based. |

## Related building blocks (not approval gateways)

- **OpenClaw SecretRef providers** — OpenClaw can resolve config secrets from
  **1Password** (`op`) or **Bitwarden Secrets Manager** (`bws`) at startup, and
  bundles a `bitwarden`/`1password` agent skill.
  https://docs.openclaw.ai/gateway/secrets/integration-examples ·
  https://github.com/openclaw/openclaw/blob/main/scripts/secrets/openclaw-bws-resolver.mjs
  These inject secrets into OpenClaw itself; they are **not** a per-request human
  approval gate, and `bws` is Secrets-Manager-only (not personal vault logins).
- **rbw** (https://github.com/doy/rbw), **Vaultwarden**
  (https://github.com/dani-garcia/vaultwarden) — vault client / self-hosted
  server; infrastructure, no agent-approval layer.

## How OpenClaw consumes MCP (so this server fits)

OpenClaw defines outbound MCP servers under `mcp.servers` and supports
`transport: "streamable-http"` with static `headers` (e.g. a bearer token),
timeouts, and `toolFilter`. Exactly the shape `bwgate` serves.
Refs: https://docs.openclaw.ai/cli/mcp/transports ·
https://docs.openclaw.ai/tools/mcp · https://docs.openclaw.ai/gateway/config-extensions

## Conclusion / recommendation

- For the **strongest security** and if you can adopt their flow, **Bitwarden
  Agent Access** is the right long-term answer for Bitwarden: it's official,
  open, and *injects* credentials so the model never sees them. Its gaps for this
  task: early-preview, approval happens on the paired device (no Telegram), and
  it's not an MCP HTTP server for arbitrary remote agents.
- The Telegram-based gates that exist (**Secret Gate**, **op-remote**,
  **Agent Vault**) are all **1Password-first**; none ships Bitwarden/Vaultwarden
  + Telegram + remote MCP over HTTP today.
- The Bitwarden/Vaultwarden MCP servers that exist have **no per-request human
  approval** (or only a local desktop/OAuth-scope prompt) and most drag in
  Node + the `bw` CLI, which is heavy on Alpine.

So there is **no off-the-shelf project** matching "lightweight Alpine server +
Bitwarden/Vaultwarden + Telegram Allow/Decline per request + remote MCP over
HTTP." Building `bwgate` is justified. Design choices borrow the good ideas from
the above: single-use scoped tokens minted only by the operator's tap
(Telegram-Bot-MCP), metadata-only prompts and field-level release
(Agent Access / vaultgate), and the option to return just the fields asked for.
A future enhancement could add an `exec_with_secret`-style injection mode (like
Secret Gate / Agent Access) so approved secrets never enter the model context.
