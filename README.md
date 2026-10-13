# bitwarden-approval-mcp (`bwgate`)

A small, single-binary **MCP server that gates Bitwarden / Vaultwarden vault
access behind human approval on Telegram.** When an agent asks for a credential,
the owner gets a Telegram message with the agent, item, fields, and reason.
The owner can approve once, for 15 minutes, for 1 hour, or forever.
Saved approvals cover only that agent, item, and approved fields.
Secret values never go to Telegram or the audit log.

Built for the OpenClaw "working agents need secrets, but not standing access to
my whole vault" use case. Runs as a static binary on Alpine (musl), ~9 MB
binary / ~19 MB image, no Node.js and no `bw` CLI required.

```
agent ──MCP(HTTP+bearer)──▶ bwgate ──▶ Telegram approval prompt ──▶ owner's phone
                              │                                           │
                              └────────── secret released only with approval ──┘
   bwgate keeps the vault unlocked in memory; it talks to Bitwarden's API directly.
```

## Status / what was tested

All unit tests and an end-to-end suite pass, the latter driving a **real
Vaultwarden container** and a **mock Telegram Bot API** through a **real MCP
client over HTTP**, plus a container-level smoke test of the shipped Alpine
image. See [Testing](#testing).

---

## Features

- **Owner-controlled credential reads.** `get_credential` and `get_totp` require
  an active saved approval or a new decision on Telegram. The owner can approve
  once, for 15 minutes, for 1 hour, or forever.
- **Metadata search is separate from secret access.** `search_items` returns
  names, URLs, folders and *which* fields exist — never values — and can be left
  ungated so agents can discover item ids without pinging your phone.
- **Secrets never touch Telegram or logs.** The approval message and audit log
  only ever contain metadata (item name, field names, reason, request id).
- **Owner-only decisions.** Only the configured Telegram user can approve.
  Each button uses a random 128-bit nonce and resolves its request once.
  Unanswered requests expire after a configurable timeout.
- **Saved approvals with a limited scope.** Approvals cover the authenticated
  agent, stable item ID, and individual fields. Timed approvals expire without
  extending on reuse. Saved approvals survive restarts and contain no secrets.
  Item policy and rate limits still apply to every read.
- **Per-agent bearer tokens**, localhost bind by default, item allow/deny lists,
  per-agent rate limiting, and a JSON-lines audit log.
- **TOTP done right:** the `totp` field returns a *generated 6-digit code*, not
  the seed. Supports SHA1/256/512 and Steam.
- **Direct Bitwarden API client** with client-side decryption (PBKDF2 &
  Argon2id, AES-CBC-256+HMAC, RSA-OAEP). Works with bitwarden.com,
  bitwarden.eu and self-hosted Vaultwarden.
- Streamable **HTTP** transport (for remote agents) and optional **stdio**.

## MCP tools

| Tool | Gated? | Returns |
| --- | --- | --- |
| `search_items` | No (configurable via `BWGATE_LIST_UNGATED`) | Item metadata: id, name, type, folder, org, URIs, and `available_fields`. No secrets. |
| `get_credential` | **Yes** | Requested fields (`username`, `password`, `totp`, `notes`, `uris`, `field:<name>`) after a new or saved owner approval. |
| `get_totp` | **Yes** | The current TOTP code and seconds remaining, after a new or saved owner approval. |

`get_credential` / `get_totp` arguments: `item` (id or exact name), `fields`
(for `get_credential`), and a `reason` string that is shown to the owner.

---

## Download release binaries

Prebuilt static binaries (`CGO_ENABLED=0`, no libc dependency, run on Alpine as-is) are attached to each
[GitHub release](https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases) for
linux amd64/arm64/armv7, macOS amd64/arm64 and Windows amd64, with a `SHA256SUMS` file.

```sh
V=0.1.0
wget https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases/download/v$V/bwgate_${V}_linux_amd64.tar.gz
wget https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases/download/v$V/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf bwgate_${V}_linux_amd64.tar.gz
install -m 0755 bwgate_${V}_linux_amd64/bwgate /usr/local/bin/bwgate
bwgate --version
```

Releases are built by `.github/workflows/release.yml` when a `v*` tag is pushed.

## Quick start on Alpine

### Option A — Docker (recommended)

```sh
git clone <this repo> bwgate && cd bwgate
docker build -t bwgate:0.1.0 .

mkdir -p secrets
printf '%s' 'your-bitwarden-master-password' > secrets/bw_password
printf '%s' '123456:your-telegram-bot-token'  > secrets/tg_token
printf '%s' "deployer:$(openssl rand -hex 24)" > secrets/agent_tokens
chmod 600 secrets/*

cp docker-compose.example.yml docker-compose.yml   # edit BW_SERVER, BW_EMAIL, owner id
docker compose up -d
docker compose logs -f           # look for "vault unlocked" and "serving MCP"
curl -s localhost:8099/healthz   # {"status":"ok","items":N,"pending":0,"locked":false}
```

### Option B — bare Alpine + OpenRC

See [Run as a service (start on boot)](#run-as-a-service-start-on-boot) for the full setup.

```sh
# Build a static binary (on any machine with Go 1.26+ (toolchain auto-downloads)):
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bwgate ./cmd/bwgate
# On the Alpine host:
apk add ca-certificates tzdata
install -m0755 bwgate /usr/local/bin/bwgate
install -m0755 deploy/bwgate.openrc /etc/init.d/bwgate
addgroup -S bwgate && adduser -S -G bwgate -H bwgate

mkdir -p /etc/bwgate /var/lib/bwgate /var/log/bwgate
chown bwgate:bwgate /var/lib/bwgate /var/log/bwgate
# Create /etc/bwgate/bwgate.env from .env.example, using *_FILE for secrets.
chmod 600 /etc/bwgate/bwgate.env

rc-update add bwgate default
rc-service bwgate start
```

---

## Run as a service (start on boot)

### Alpine / OpenRC

The init script [`deploy/bwgate.openrc`](deploy/bwgate.openrc) expects:

| What | Path |
|---|---|
| Binary | `/usr/local/bin/bwgate` |
| Service user/group | `bwgate:bwgate` |
| Env file (shell-sourced, `KEY=value`) | `/etc/bwgate/bwgate.env` |
| Secret files | `/etc/bwgate/secrets/*` (referenced via `*_FILE`) |
| Log (stdout+stderr) | `/var/log/bwgate/bwgate.log` |
| State / audit log | `/var/lib/bwgate/` |

Run as root:

```sh
apk add ca-certificates tzdata

# 1. Binary (use _linux_arm64 / _linux_armv7 on ARM)
V=0.1.0; cd /tmp
wget https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases/download/v$V/bwgate_${V}_linux_amd64.tar.gz
wget https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases/download/v$V/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf bwgate_${V}_linux_amd64.tar.gz
install -m 0755 bwgate_${V}_linux_amd64/bwgate /usr/local/bin/bwgate

# 2. Dedicated system user (no login, no home)
addgroup -S bwgate
adduser -S -D -H -h /var/lib/bwgate -s /sbin/nologin -G bwgate bwgate

# 3. Config + secrets, readable only by bwgate
install -d -m 0750 -o root -g bwgate /etc/bwgate
install -d -m 0700 -o bwgate -g bwgate /etc/bwgate/secrets
printf '%s' 'your-master-password'      > /etc/bwgate/secrets/bw_password
printf '%s' '123456:telegram-bot-token' > /etc/bwgate/secrets/tg_token
printf '%s' "deployer:$(openssl rand -hex 24)" > /etc/bwgate/secrets/agent_tokens
cat > /etc/bwgate/bwgate.env <<'ENV'
BW_SERVER=https://vault.bitwarden.com
BW_EMAIL=you@example.com
BW_PASSWORD_FILE=/etc/bwgate/secrets/bw_password
TELEGRAM_BOT_TOKEN_FILE=/etc/bwgate/secrets/tg_token
TELEGRAM_OWNER_USER_ID=11111111
BWGATE_AGENT_TOKENS_FILE=/etc/bwgate/secrets/agent_tokens
BWGATE_ADDR=127.0.0.1:8099
BWGATE_AUDIT_LOG=/var/lib/bwgate/audit.log
BWGATE_APPROVALS_FILE=/var/lib/bwgate/approvals.json
ENV
chown bwgate:bwgate /etc/bwgate/bwgate.env /etc/bwgate/secrets/*
chmod 600 /etc/bwgate/bwgate.env /etc/bwgate/secrets/*

# 4. Init script, enable at boot, start
wget -O /etc/init.d/bwgate https://raw.githubusercontent.com/LionZXYAgent/bitwarden-approval-mcp/master/deploy/bwgate.openrc
chmod 0755 /etc/init.d/bwgate
rc-update add bwgate default
rc-service bwgate start
```

The script creates `/var/log/bwgate` and `/var/lib/bwgate` itself, waits for `net`, and runs the binary as `bwgate`
(not root). Use a different env file with `BWGATE_ENV_FILE=/path` in `/etc/conf.d/bwgate`.

Status and logs:

```sh
rc-service bwgate status
tail -f /var/log/bwgate/bwgate.log   # look for "vault unlocked" and "serving MCP"
curl -s localhost:8099/healthz
```

Confirm it starts on boot:

```sh
rc-update show default | grep bwgate   # bwgate | default
reboot
# after reboot:
rc-service bwgate status && curl -s localhost:8099/healthz
```

### systemd (Debian, Ubuntu, etc.)

Same user, `/etc/bwgate/bwgate.env` and secrets as above (on Debian use
`useradd --system --no-create-home --shell /usr/sbin/nologin bwgate`). The env file must be plain `KEY=value`
lines: systemd does not allow inline comments. The unit [`deploy/bwgate.service`](deploy/bwgate.service) is hardened
(`NoNewPrivileges`, `ProtectSystem=strict`, no capabilities, syscall filter) and restarts on failure.

```sh
install -m 0644 deploy/bwgate.service /etc/systemd/system/bwgate.service
systemctl daemon-reload
systemctl enable --now bwgate
systemctl status bwgate
journalctl -u bwgate -f
systemctl is-enabled bwgate   # enabled = starts on boot
```

## Create the Telegram bot

1. In Telegram, message **@BotFather** → `/newbot`, pick a name and username,
   and copy the **bot token** (looks like `123456789:AA...`). Put it in
   `secrets/tg_token` (or `TELEGRAM_BOT_TOKEN_FILE`).
2. Find **your own numeric user id**: message **@userinfobot** (or
   **@RawDataBot**) and read the `id`. Set `TELEGRAM_OWNER_USER_ID` to it. This
   is the *only* account whose button presses are honoured.
3. **Send your bot a message first** (e.g. `/start`). A bot cannot open a chat
   with you; it can only reply. After you message it once, `bwgate` can deliver
   approval prompts to your private chat (chat id defaults to your user id). To
   send prompts to a group instead, add the bot to the group and set
   `TELEGRAM_OWNER_CHAT_ID` to the group id.
4. `bwgate` uses long polling (`getUpdates`); no public webhook/URL is needed.
   Don't run a second `getUpdates` consumer (or a webhook) for the same bot — the
   Telegram API allows only one, and `bwgate` will report a conflict and stop.

---

## Configuration

Everything is set via environment variables. **Every secret also accepts a
`<NAME>_FILE` variant** that reads the value from a file (Docker/Podman secrets
style); the file form takes precedence and keeps secrets out of the process
environment and `docker inspect`.

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `BW_SERVER` | – | `https://vault.bitwarden.com` | Use your Vaultwarden URL for self-hosted. `.eu` auto-detected. |
| `BW_API_URL`, `BW_IDENTITY_URL` | – | derived | Override API/identity endpoints if needed. |
| `BW_EMAIL` | ✅ | – | Vault account email. |
| `BW_PASSWORD` / `BW_PASSWORD_FILE` | ✅ | – | Master password. Needed to decrypt the vault; wiped from memory after unlock. |
| `BW_CLIENTID`, `BW_CLIENTSECRET` / `_FILE` | – | – | Personal API key. Recommended on bitwarden.com to avoid captcha/2FA on login; still needs the master password to decrypt. |
| `BW_DEVICE_ID` | – | random | Stable device UUID (reduces new-device emails). |
| `TELEGRAM_BOT_TOKEN` / `_FILE` | ✅ | – | From @BotFather. |
| `TELEGRAM_OWNER_USER_ID` | ✅ | – | Your numeric Telegram user id; only this user may approve. |
| `TELEGRAM_OWNER_CHAT_ID` | – | = user id | Where prompts are sent (set for a group). |
| `TELEGRAM_API_BASE` | – | `https://api.telegram.org` | For testing against a mock. |
| `BWGATE_AGENT_TOKENS` / `_FILE` | ✅ | – | `name:token,name:token`. Tokens ≥16 chars; generate with `openssl rand -hex 24`. |
| `BWGATE_AGENTS_FILE` | – | – | Alternative: one `name:token` per line. |
| `BWGATE_ADDR` | – | `127.0.0.1:8099` | Bind address. Localhost by default. |
| `BWGATE_TRANSPORT` | – | `http` | `http`, `stdio`, or `both`. |
| `BWGATE_APPROVAL_TIMEOUT_SEC` | – | `120` | Auto-decline unanswered prompts after this long. |
| `BWGATE_APPROVALS_FILE` | – | `approvals.json` | File for saved approvals. Its directory must exist and be writable. Use persistent storage. |
| `BWGATE_LIST_UNGATED` | – | `true` | If `false`, `search_items` is unavailable (list via gated reads only). |
| `BWGATE_ALLOWLIST` / `BWGATE_DENYLIST` | – | – | Comma-separated globs matched on item name or id; **deny wins**. Empty allowlist = allow all. |
| `BWGATE_MAX_PENDING_PER_AGENT` | – | `3` | Back-pressure per agent. |
| `BWGATE_MAX_PENDING_TOTAL` | – | `20` | Global pending cap. |
| `BWGATE_RATE_LIMIT_PER_MIN` | – | `30` | Gated requests per agent per minute. |
| `BWGATE_SYNC_INTERVAL_SEC` | – | `900` | Background vault re-sync; `0` disables. |
| `BWGATE_AUDIT_LOG` | – | `-` (stderr) | Path to a JSON-lines audit file. |
| `TZ` | – | `UTC` | Timestamp zone in the approval prompt. |

### What the approval message looks like

```
🔐 Credential request

Item: GitHub
Folder: Work
Fields: username, password
Agent: deployer
Client: openclaw/1.x
Reason: deploy release v2 to prod

Request 6ommlg · 2026-10-07 20:35:06 BST
Expires in 2m0s. No secret values are shown here.
Saved approvals cover only this agent, item, and these fields.
      [ ✅ Allow once ]
      [ Approve for 15 min ]
      [ Approve for 1h ]
      [ Approve forever ]
      [ ⛔ Decline ]
```

After a decision the same message is edited to `✅ ALLOWED` / `⛔ DECLINED` /
`⌛ TIMED OUT`, with the request ID, approver, and approval duration.

The 15-minute and 1-hour periods start when the owner presses the button.
Later reads of approved fields return without a new prompt until approval expires.
A request for additional fields still requires approval.
A saved `totp` approval covers both `get_totp` and the `totp` field of `get_credential`.
New reads fetch current vault values, not cached secret values.

Forever approvals have no expiry and survive restarts.
To revoke saved approvals, stop `bwgate`, delete `BWGATE_APPROVALS_FILE`, then start `bwgate`.
The next read requires a new approval. Existing copies of released secrets remain with their recipients.
The file contains permission metadata only and uses mode `0600`.
If a saved approval cannot be written, the request stays pending. The owner can retry or choose Allow once.

---

## OpenClaw integration

`bwgate` speaks streamable HTTP MCP, which OpenClaw consumes natively. Add it
under `mcp.servers` (keep the bearer token out of the committed config — use a
`${ENV}` reference or OpenClaw's secret mechanism):

```json5
{
  mcp: {
    servers: {
      bitwarden: {
        url: "http://127.0.0.1:8099/mcp",
        transport: "streamable-http",
        connectionTimeoutMs: 5000,
        // get_credential blocks until you tap Allow, so allow a generous window:
        requestTimeoutMs: 130000,
        headers: {
          Authorization: "Bearer ${BWGATE_DEPLOYER_TOKEN}",
        },
        toolFilter: { include: ["search_items", "get_credential", "get_totp"] },
      },
    },
  },
}
```

Or via the CLI:

```sh
openclaw mcp add bitwarden \
  --url http://127.0.0.1:8099/mcp \
  --transport streamable-http \
  --timeout 130 --connect-timeout 5 \
  --include 'search_items,get_credential,get_totp'
openclaw mcp doctor bitwarden --probe
```

Give each agent/runtime its own token in `BWGATE_AGENT_TOKENS` so the approval
prompt and audit log can tell them apart. For other MCP clients (Claude Code,
Codex, Cursor, MCP Inspector) point them at the same URL with the bearer header.

---

## Testing

```sh
go test ./...          # unit tests (crypto, TOTP, approval FSM, policy, config, audit)
go test -race ./...    # same, race detector clean
```

End-to-end (needs Docker/Podman for Vaultwarden):

```sh
docker run -d --name vw -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
  -p 127.0.0.1:8111:80 vaultwarden/server:latest-alpine
VW_BASE=http://127.0.0.1:8111 go test -tags e2e ./test/e2e/ -v
```

The e2e suite registers a throwaway account, seeds items (with client-side
encryption), unlocks the vault with the real client, and — through a **real MCP
client over HTTP** against a **mock Telegram Bot API** — covers: auth required,
ungated search, approve, decline, wrong-user press (ignored → timeout), policy
deny, and TOTP. It asserts secrets never appear in the Telegram text or audit
log. No real credentials are used.

---

## Security model

**What it protects.** Agents never hold your master password or a standing vault
session. They get individual fields, one approval at a time, scoped by allow/deny
lists and rate limits. Each read requires a new decision or an active saved approval.
The agent only receives the fields that it requests.
Saved approvals do not extend to other agents, items, or unapproved fields.

- **Secrets stay off Telegram and off disk logs.** Only metadata is sent to
  Telegram or written to the audit log. Verified by tests.
- **The approval channel is authenticated.** Only `TELEGRAM_OWNER_USER_ID` can
  approve; other users' presses are logged (`wrong_user_press`) and refused.
  Callback data uses a random 128-bit nonce. A button cannot resolve its request
  twice or create an approval after the prompt expires.
- **Agents are authenticated** with per-agent bearer tokens (constant-time
  compare). Default bind is localhost; the HTTP handler also applies the MCP
  SDK's DNS-rebinding/cross-origin protections.
- **Vault session lives in memory only** and is locked (keys zeroed) on
  shutdown. The master password is wiped right after unlock.
- **Secrets come from env or files;** `*_FILE` is preferred and nothing secret is
  logged.

**Limitations / threat model — read before trusting it.**

- **`bwgate` is as trusted as the host it runs on.** It holds an unlocked vault
  in process memory; anyone with root / ptrace / a memory dump on that host can
  extract secrets. Run it on a machine you trust, as the unprivileged `bwgate`
  user, ideally isolated from the agents it serves.
- **Approval proves intent, not safety.** Once you tap *Allow*, the plaintext
  secret goes to the agent and into its model context. If the agent is
  compromised or prompt-injected, approval doesn't stop misuse — it only ensures
  a human chose to release *that* item. This is a deliberately weaker model than
  Bitwarden Agent Access / 1Password for Claude, which inject credentials without
  the model ever seeing them. Use allow/deny lists and short timeouts, and don't
  approve requests whose reason you don't understand (the reason is
  agent-supplied and untrusted).
- **Telegram is the approval channel.** You trust Telegram's transport and your
  own account's security (use 2FA). The bot token grants send/poll on that bot;
  keep it secret. Long polling means one consumer per bot.
- **No TLS termination built in.** For remote agents, bind to localhost and put
  it behind an SSH tunnel, WireGuard, or a reverse proxy that adds TLS — don't
  expose `:8099` to the internet directly.
- **Transport auth is a static bearer token**, not OAuth; rotate tokens by
  editing config and restarting. There is no per-call mTLS.
- **2FA on login:** interactive TOTP/email 2FA on the *vault account* login is
  not handled; use a personal API key (`BW_CLIENTID`/`BW_CLIENTSECRET`) for
  accounts with 2FA. (This is 2FA to log into Bitwarden, distinct from the
  `get_totp` tool which reads 2FA codes *stored in* the vault.)
- Not implemented: writing/editing items, attachments, Sends, organization
  admin, or credential *injection* (secrets are returned to the caller).

## Why this stack

- **Go, static, CGO-off:** one ~9 MB binary that runs on bare Alpine/musl with
  no runtime deps — ideal for a small always-on approval daemon. The official
  Bitwarden MCP server is Node/`npx` + the `bw` CLI, which is much heavier on
  Alpine.
- **Direct Bitwarden API instead of the `bw` CLI or `bw serve`:** avoids bundling
  Node and a ~100 MB toolchain, keeps the unlocked session inside our own process
  (so we control locking and never shell out), and lets us return exactly the
  requested fields. `rbw`/`bws` were considered; `bws` is Secrets-Manager-only
  (not personal vault items) and `rbw` is another external process to manage.
- **Telegram long polling, no webhook:** no inbound port, no public URL, works
  from behind NAT — which suits a daemon on a home server or small VM.

See `RESEARCH.md` for the survey of existing tools and why none fit this exact
requirement off the shelf.

## License

MIT. See `LICENSE`.
