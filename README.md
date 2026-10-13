# bitwarden-approval-mcp (`bwgate`)

Give AI agents access to Bitwarden or Vaultwarden credentials with owner approval on Telegram.
`bwgate` uses MCP (Model Context Protocol), which connects agents to tools.
It runs as one Go binary, including on Alpine, without Node.js or the `bw` CLI.

The owner sees the requesting agent, item, fields, and reason before approving.
The audit log records requests and approval decisions.
Secret values go only to the agent, never to Telegram or the audit log.

## Quick start with Docker

Use a host with Docker Compose, Git, and OpenSSL installed.
You also need a Bitwarden or Vaultwarden account and a Telegram bot.
Run the commands below on the host that will run `bwgate`.

1. Create a bot through @BotFather with `/newbot`. Save its token for step 5.
2. Get your numeric Telegram user ID through @userinfobot or @RawDataBot.
3. Send `/start` to your new bot. This lets the bot send approval prompts to your private chat.
4. Clone the repository:

   ```sh
   git clone https://github.com/LionZXYAgent/bitwarden-approval-mcp.git bwgate
   cd bwgate
   docker build -t bwgate:0.1.0 .
   ```

5. Create the secret files. Replace the password and bot token placeholders:

   ```sh
   mkdir -p secrets
   printf '%s' 'your-bitwarden-master-password' > secrets/bw_password
   printf '%s' '123456:your-telegram-bot-token' > secrets/tg_token
   printf '%s' "deployer:$(openssl rand -hex 24)" > secrets/agent_tokens
   chmod 600 secrets/*
   ```

6. Copy the example configuration:

   ```sh
   cp docker-compose.example.yml docker-compose.yml
   ```

   Set `BW_SERVER`, `BW_EMAIL`, and `TELEGRAM_OWNER_USER_ID` in `docker-compose.yml`.
   Keep the `/data` volume for audit logs and saved approvals.
   Make sure that the container's `bwgate` user can write to `/data`.

7. Start the server and make sure that it responds:

   ```sh
   docker compose up -d
   docker compose logs -f
   curl -s localhost:8099/healthz
   ```

   The health response reports `status`, `items`, `pending`, and `locked`.
   The logs show `vault unlocked` and `serving MCP` after startup.

Only `TELEGRAM_OWNER_USER_ID` can approve requests.
For group prompts, add the bot to the group and set `TELEGRAM_OWNER_CHAT_ID` to the group ID.
Do not run another `getUpdates` consumer or webhook with the same bot. A conflict stops the approval loop.

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
Use the token after `deployer:` in `secrets/agent_tokens`.
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

## Run without Docker

Download a binary and `SHA256SUMS` from [GitHub Releases](https://github.com/LionZXYAgent/bitwarden-approval-mcp/releases).
A checksum detects changes in a downloaded file.
Make sure that the checksum matches before installing the binary.
Releases support Linux amd64/arm64/armv7, macOS amd64/arm64, and Windows amd64.

To build from source, install Go 1.26 or later and run this command in the repository:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bwgate ./cmd/bwgate
```

For a service, create the `bwgate` user and install the binary at `/usr/local/bin/bwgate`.
Put configuration in `/etc/bwgate/bwgate.env`, with secrets in files referenced by `*_FILE`.
Use plain `KEY=value` lines without inline comments for systemd.
Make sure that `bwgate` can read the secret files and write its audit and approval files.
Use `/var/lib/bwgate/approvals.json` for `BWGATE_APPROVALS_FILE`.

Use the supplied service file for your host:

- Alpine: Install [deploy/bwgate.openrc](deploy/bwgate.openrc) as `/etc/init.d/bwgate` and make it executable.
- Linux with systemd: Install [deploy/bwgate.service](deploy/bwgate.service) in `/etc/systemd/system/`.
- Other hosts: Set the environment variables and run `bwgate` directly.

On Alpine, install `ca-certificates` and `tzdata`, then enable and start the service:

```sh
rc-update add bwgate default
rc-service bwgate start
```

On systemd hosts, enable and start the service after installing its unit file:

```sh
systemctl daemon-reload
systemctl enable --now bwgate
```

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
