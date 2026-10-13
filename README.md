# bitwarden-approval-mcp (`bwgate`)

Give AI agents access to Bitwarden or Vaultwarden credentials with owner approval on Telegram.
`bwgate` uses MCP (Model Context Protocol), which connects agents to tools.
It runs as one Go binary, including on Alpine, without Node.js or the `bw` CLI.

The owner sees the requesting agent, item, fields, and reason before approving.
The audit log records requests and approval decisions.
Secret values go only to the agent, never to Telegram or the audit log.

## Install on Alpine

Run these commands as root on the Alpine host that will run `bwgate`.
You need a Bitwarden or Vaultwarden account and a Telegram bot.
The service runs as the unprivileged `bwgate` user through OpenRC, Alpine's service manager.

1. Create a bot through @BotFather with `/newbot`. Save its token for step 5.
2. Get your numeric Telegram user ID through @userinfobot or @RawDataBot.
3. Send `/start` to your new bot. This lets it send approval prompts to your private chat.
4. Install the dependencies, build the binary, and install the service script:

   ```sh
   apk add ca-certificates tzdata git openssl go curl
   git clone https://github.com/LionZXYAgent/bitwarden-approval-mcp.git bwgate
   cd bwgate
   CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bwgate ./cmd/bwgate
   install -m 0755 bwgate /usr/local/bin/bwgate
   install -m 0755 deploy/bwgate.openrc /etc/init.d/bwgate
   ```

   The build requires Go 1.26 or later.
   If the packaged Go is older, Go downloads the required version automatically with the default `GOTOOLCHAIN=auto`.
   Prebuilt Alpine-compatible binaries are also available from [GitHub Releases](https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases).

5. Create the service user, directories, and secret files. Replace the password and bot token placeholders:

   ```sh
   addgroup -S bwgate
   adduser -S -D -H -s /sbin/nologin -G bwgate bwgate
   install -d -m 0750 -o root -g bwgate /etc/bwgate
   install -d -m 0700 -o bwgate -g bwgate /etc/bwgate/secrets
   install -d -m 0750 -o bwgate -g bwgate /var/lib/bwgate /var/log/bwgate
   printf '%s' 'your-bitwarden-master-password' > /etc/bwgate/secrets/bw_password
   printf '%s' '123456:your-telegram-bot-token' > /etc/bwgate/secrets/tg_token
   printf '%s' "deployer:$(openssl rand -hex 24)" > /etc/bwgate/secrets/agent_tokens
   chown bwgate:bwgate /etc/bwgate/secrets/*
   chmod 600 /etc/bwgate/secrets/*
   ```

6. Create `/etc/bwgate/bwgate.env`. Replace the server URL, email, and owner user ID:

   ```sh
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
   TZ=UTC
   ENV
   chown root:bwgate /etc/bwgate/bwgate.env
   chmod 640 /etc/bwgate/bwgate.env
   ```

7. Enable the service at boot, start it, and make sure that it responds:

   ```sh
   rc-update add bwgate default
   rc-service bwgate start
   curl -s localhost:8099/healthz
   ```

   The health response reports `status`, `items`, `pending`, and `locked`.
   Read `/var/log/bwgate/bwgate.log` for startup errors.
   Use `rc-service bwgate status` to see whether the service runs.

Only `TELEGRAM_OWNER_USER_ID` can approve requests.
For group prompts, add the bot to the group and set `TELEGRAM_OWNER_CHAT_ID` to the group ID.
Do not run another `getUpdates` consumer or webhook with the same bot. A conflict stops the approval loop.

## Update on Alpine

Run this one-line command as root from your existing source checkout on the Alpine host:

```sh
git pull --ff-only && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bwgate ./cmd/bwgate && rc-service bwgate stop && install -m 0755 bwgate /usr/local/bin/bwgate && rc-service bwgate start
```

It updates the current branch and builds the new binary before stopping the service.
It replaces the binary, then starts `bwgate` again.
Your configuration, secret files, audit log, and saved approvals stay in place.

## Tools and approvals

Search returns item details but no secret values.
Credential reads require a new Telegram decision or an active saved approval.
Use the item ID from `search_items` when requesting credentials.

| Tool | Input | Result |
| --- | --- | --- |
| `search_items` | Optional `query` | Item IDs, names, URLs, folders, and available fields. |
| `get_credential` | `item`, `fields`, `reason` | Requested fields after approval. |
| `get_totp` | `item`, `reason` | Current two-factor authentication code and seconds remaining. |

Supported fields are `username`, `password`, `totp`, `notes`, `uris`, and `field:<name>` for custom fields.
TOTP means time-based one-time password. Both credential tools return a generated code, never its seed.
The `reason` appears in the approval prompt and must not be empty.

| Telegram button | Access granted |
| --- | --- |
| Allow once | This request only. |
| Approve for 15 min | Approved fields for 15 minutes. |
| Approve for 1h | Approved fields for 1 hour. |
| Approve forever | Approved fields without an expiry. |
| Decline | No access for this request. |

Saved approvals cover only the authenticated agent, item ID, and approved fields.
They apply across both credential tools when the requested fields match.
Timed approvals start at the button press and do not extend when reused.
Requests for other agents, items, or additional fields need a new approval.
Item rules and request limits still apply to every read.
Unanswered prompts expire after 120 seconds by default.

Saved approvals survive restarts through `BWGATE_APPROVALS_FILE`.
The file contains permission details only and uses mode `0600`.
Its directory must exist and be writable by `bwgate`.
If saving fails, the request stays pending. Retry or choose Allow once.

To revoke all saved approvals on the server host:

1. Stop `bwgate`.
2. Delete the file named by `BWGATE_APPROVALS_FILE`.
3. Start `bwgate`.

Revocation does not remove secret copies already returned to agents.

## Connect an agent

Clients connect to `http://127.0.0.1:8099/mcp` with a bearer token, an access key sent with each request.
Use the token after `deployer:` in `/etc/bwgate/secrets/agent_tokens`.
Give each agent a separate name and token so approvals remain separate.

For OpenClaw, add this configuration under `mcp.servers`.
Set `BWGATE_DEPLOYER_TOKEN` in the OpenClaw environment to the agent token.
Keep the token out of committed configuration files.

```json5
{
  mcp: {
    servers: {
      bitwarden: {
        url: "http://127.0.0.1:8099/mcp",
        transport: "streamable-http",
        connectionTimeoutMs: 5000,
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

Set the client timeout above `BWGATE_APPROVAL_TIMEOUT_SEC` so the owner has time to respond.
Other MCP clients use the same URL and `Authorization: Bearer <token>` header.
For remote access, use an SSH tunnel, WireGuard, or a reverse proxy with HTTPS.
Do not expose port `8099` directly to the internet. `bwgate` does not encrypt HTTP connections.

## Configuration

Set configuration through environment variables.
For secrets, use `<NAME>_FILE` to read a file instead of storing the value in the environment.
The file takes precedence. See [.env.example](.env.example) for a starting configuration.

| Required variable | Value |
| --- | --- |
| `BW_EMAIL` | Vault account email. |
| `BW_PASSWORD` / `BW_PASSWORD_FILE` | Master password for vault decryption. |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_BOT_TOKEN_FILE` | BotFather token. |
| `TELEGRAM_OWNER_USER_ID` | Numeric ID of the only user who can approve. |
| `BWGATE_AGENT_TOKENS` / `BWGATE_AGENT_TOKENS_FILE` | Comma-separated `name:token` pairs. Each token needs at least 16 characters. |

| Optional variable | Default | Purpose |
| --- | --- | --- |
| `BW_SERVER` | `https://vault.bitwarden.com` | Bitwarden or Vaultwarden URL. Also supports `https://vault.bitwarden.eu`. |
| `BW_CLIENTID`, `BW_CLIENTSECRET` / `BW_CLIENTSECRET_FILE` | None | Personal API key for accounts with two-factor authentication. The master password is still required. |
| `TELEGRAM_OWNER_CHAT_ID` | Owner user ID | Private chat or group that receives prompts. |
| `BWGATE_ADDR` | `127.0.0.1:8099` | Address for incoming connections. |
| `BWGATE_TRANSPORT` | `http` | `http`, `stdio`, or `both`. `stdio` uses standard input and output. |
| `BWGATE_APPROVAL_TIMEOUT_SEC` | `120` | Time before an unanswered prompt expires. Minimum: `5`. |
| `BWGATE_APPROVALS_FILE` | `approvals.json` | Path for saved approvals. Use persistent storage. |
| `BWGATE_ALLOWLIST`, `BWGATE_DENYLIST` | Empty | Comma-separated patterns for item names or IDs. Deny wins. An empty allowlist allows all items. |
| `BWGATE_MAX_PENDING_PER_AGENT` | `3` | Maximum unanswered requests per agent. |
| `BWGATE_MAX_PENDING_TOTAL` | `20` | Maximum unanswered requests across all agents. |
| `BWGATE_RATE_LIMIT_PER_MIN` | `30` | Credential requests per agent per minute, including saved approvals. |
| `BWGATE_SYNC_INTERVAL_SEC` | `900` | Vault refresh interval. `0` disables refresh. |
| `BWGATE_AUDIT_LOG` | `-` | Audit file path. `-` writes to standard error. |
| `TZ` | `UTC` | Time zone for approval messages. |

## Limits and development

Run `bwgate` on a trusted host as an unprivileged user. It holds an unlocked vault in memory.
Approval releases readable secrets to the agent. It does not prevent the agent from misusing them.
Request reasons come from agents, so approve only requests that you understand.

Interactive vault login with two-factor authentication is not supported. Use a personal API key for those accounts.
The server reads credentials only. It does not edit items, handle attachments, or manage organizations.

Run these commands in the repository for code checks and unit tests:

```sh
go vet ./...
go test ./...
go test -race ./...
```

The [end-to-end tests](test/e2e) use a real Vaultwarden server and a mock Telegram API.
With Vaultwarden running at `http://127.0.0.1:8111`, run `make e2e`.
See [RESEARCH.md](RESEARCH.md) for the comparison of existing tools.
The project uses the [MIT license](LICENSE).
