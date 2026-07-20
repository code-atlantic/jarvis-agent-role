# Jarvis Agent Role

A self-contained WordPress plugin that provisions a dedicated, least-privilege user for an
AI agent — a version-controlled `jarvis_agent` role, an auto-created agent user with a local
avatar, a tamper-aware audit trail of every agent action, and an optional read-only SQL
ability. Built for sites driven by MCP / REST tooling, where the agent needs broad *content*
powers but must never be able to execute code or escalate accounts.

Fork it, rename the identity via filters (or in code), and you have a hardened agent
account for your own AI integration.

## What you get

- **`jarvis_agent` role, defined in code.** The capability list in
  `jarvis-agent-role.php` is the single source of truth. Bump `ROLE_VERSION` and the stored
  role rebuilds on the next admin load — no deactivate/reactivate dance.
- **A provisioned agent user.** Activation creates a `jarvis` user on the role, with
  display name, bio, and a bundled avatar served locally everywhere WordPress renders
  one — no Gravatar dependency. Login, email, and bio are all filterable (see
  [Configuration](#configuration-reference)); set a real email for your site.
- **An audit log** of every Abilities-API tool call, auth event, and WP-CLI command,
  written as JSON lines to a file outside the web root.
- **An optional read-only SQL ability** (`jarvis/execute-sql`) for ad-hoc reporting,
  off by default and triple-gated when on.

## Security model: "Admin-minus"

The agent gets everything content/MCP tooling exercises — including `manage_options` —
but **none** of the capabilities that allow code execution or account escalation.
Deliberately withheld:

- `install_plugins`, `activate_plugins`, `edit_plugins`, `edit_themes`, `edit_files`
- `update_core`, `update_plugins`, `update_themes`
- `create_users`, `edit_users`, `delete_users`, `promote_users`
- `unfiltered_html`, `export`, `import`

A leaked credential can edit content and settings — it cannot run arbitrary PHP or take
over accounts. Auth is via [application passwords](https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/)
(revocable, per-site), never an interactive login: the account is created with an unused
cryptographically random password.

## Custom post types — derived, not hand-listed

CPTs often register custom capability types, so generic `edit_posts` doesn't cover them.
Rather than maintain a hand-list that rots, `derive_cpt_capabilities()` walks `post`,
`page`, and every `show_in_rest` post type and pulls each one's mapped
`edit_posts` / `edit_others_posts` / `edit_published_posts` / `publish_posts` cap names off
its capability object — e.g. a `popup` CPT yields `edit_popups`, a `download` CPT with
`capability_type => 'product'` yields `edit_products`, automatically.

Because activation can run before other plugins register their CPTs, missing derived caps
are re-asserted on every `admin_init` (a cheap no-op once present). A new CPT appears →
the next admin load grants its caps. Delete-class primitives are deliberately not derived.

The stock list also includes capabilities for Easy Digital Downloads, Popup Maker,
FluentCRM, and FluentBoards — trim those in `capabilities()` (or via the filter below)
if your stack differs.

## Installation & provisioning

1. Copy this folder into `wp-content/plugins/` and activate
   (or `wp plugin activate jarvis-agent-role`). Activation registers the role, then
   creates the agent user on it if it doesn't already exist. Idempotent — re-activating
   won't duplicate or clobber.
2. Generate an application password for the agent:

   ```bash
   wp user application-password create jarvis "jarvis-mcp" --porcelain
   ```

   Store the returned token in your MCP/agent config for that site. Rotate by deleting
   and re-creating the application password — the role and other sites are untouched.

`wp jarvis user` re-runs the provisioning check on demand (and prints the app-password
command).

### Set your own agent identity

The defaults are deliberately generic: login `jarvis`, email `jarvis@example.com`
(RFC 2606 reserved — it can never be registered), and a neutral bio. Set your own in
`wp-config.php` — this is the recommended approach, and it keeps your real agent
identity out of the plugin and out of version control:

```php
// wp-config.php
define( 'JARVIS_USER_LOGIN', 'friday' );
define( 'JARVIS_USER_EMAIL', 'agent@yourcompany.com' );
define( 'JARVIS_USER_BIO',   'Our AI agent. Scoped permissions, fully logged.' );
```

Equivalent filters (`jarvis_user_login`, `jarvis_user_email`, `jarvis_user_bio`) are
available for programmatic cases and **take precedence over the constants**.

Set these **before** first activation so the user is created with them. If the account
already exists, run `wp jarvis user` to re-assert display name, nickname, and bio.
Changing the *login* after creation does not rename the existing account — provisioning
then looks for a different user and will refuse to adopt one that isn't unambiguously
the agent (see below); rename the account in WordPress instead.

> The agent account never logs in interactively — it's created with an unused random
> password and authenticates via application password — so a predictable login is not
> itself a weakness. The security boundary is the capability ceiling and the revocable
> credential, not the username.

### Safety: account adoption rules

- A pre-existing account is **adopted** only when **both** the login *and* the email match
  the canonical agent identity and resolve to the same user — i.e. the account you'd have
  created yourself (e.g. earlier via `wp user create`). It's then flagged, given the role,
  and its identity re-asserted.
- If the login **or** the email collides with a *different* account, provisioning
  **refuses** — it will not bolt an agent role onto a real person's user. Change the
  identity via the `jarvis_user_login` / `jarvis_user_email` filters, or flag the intended
  account manually (`wp user meta update <id> _jarvis_agent_user 1`) and run
  `wp jarvis user`.

## Audit log

Captured at the **Abilities API layer**: WordPress fires
`wp_before_execute_ability` / `wp_after_execute_ability` around every ability execution,
so one pair of hooks logs every MCP/agent tool call — core `mcp-adapter`, third-party
adapters, and any custom tool added later — without touching core or vendor files.
Auth events (cookie login + application-password) are captured separately.

- Ability and auth logging fires **only** for `jarvis_agent` users — humans and other API
  clients log nothing there.
- **WP-CLI commands are logged unconditionally** (not gated on the role): every `wp`
  command is privileged shell access worth auditing, and it usually runs with no `--user`.
  Each entry records the command, the OS user, and the SSH client, so the trail ties back
  to who was on the box.
- Each `ability` entry records the tool name, full input args, and `ok`/`error` status.
  Result bodies are not logged (inputs already capture what changed; read payloads are
  noise). Credential-shaped keys (`password`, `token`, `secret`, `api_key`, …) are
  redacted so the log never becomes a secret sink. Oversized inputs are clipped at 20 KB.

### Location & usage

Defaults to `jarvis-audit/jarvis-audit.log` one level **above** `wp-content` (typically
above the web root, so the trail isn't web-reachable) when writable; otherwise falls back
to `wp-content/jarvis-audit.log`. Override explicitly:

```php
// wp-config.php
define( 'JARVIS_AUDIT_LOG_FILE', '/var/log/jarvis/audit.log' );
```

```bash
wp jarvis audit --lines=50   # last 50 events (prints the resolved path too)
```

- Rotates at 10 MB (keeps one `.1` backup). Self-bounding; no cleanup needed.
- Writes fail silently by design — auditing never breaks the request it observes.
- **Not tamper-proof:** a `manage_options` credential could reach a log inside the tree.
  For a defensible trail, point `JARVIS_AUDIT_LOG_FILE` somewhere the web user can append
  but not read/rewrite, or ship lines to an external sink.

## Read-only SQL ability (optional, off by default)

`jarvis/execute-sql` (WP 6.9+ Abilities API) runs a **single read-only query** and returns
rows — the deliberate, scoped answer to "let the agent run ad-hoc reports". Three gates:

1. **Identity, not capability:** only the flagged agent user may call it — another admin
   with `manage_options` cannot.
2. **Statement validation:** leading-keyword allowlist (`SELECT` / `SHOW` / `DESCRIBE` /
   `EXPLAIN` / `WITH`), a mutating-keyword denylist, no statement stacking, and an
   injected `LIMIT` (1,000-row hard cap).
3. **Explicitly enabled per site:**

   ```php
   // wp-config.php
   define( 'JARVIS_ENABLE_SQL', true );
   ```

When disabled (the default) the ability isn't even registered.

## Configuration reference

| Hook / constant | Purpose |
| --- | --- |
| `jarvis_role_capabilities` (filter) | Add/drop caps per site without forking — e.g. revoke `manage_options` on a hardened install. |
| `JARVIS_USER_LOGIN` / `JARVIS_USER_EMAIL` / `JARVIS_USER_BIO` (constants) | Agent account identity. Recommended — set in `wp-config.php`. |
| `jarvis_user_login` / `jarvis_user_email` / `jarvis_user_bio` (filters) | Same values, programmatically. Take precedence over the constants. |
| `jarvis_enable_sql` (filter) / `JARVIS_ENABLE_SQL` (constant) | Enable the SQL ability. |
| `JARVIS_AUDIT_LOG_FILE` (constant) | Explicit audit-log path. |

### WP-CLI commands

| Command | Purpose |
| --- | --- |
| `wp jarvis sync` | Force a role rebuild from the capability array. |
| `wp jarvis user` | Ensure the agent user exists and its identity is current. |
| `wp jarvis audit --lines=N` | Tail the audit trail. |

## Updates (Git Updater)

The main file carries `GitHub Plugin URI` / `Primary Branch` headers, so any site with
[Git Updater](https://git-updater.com/) installed sees new tagged releases as ordinary
plugin updates.

**Cutting a release:** bump the `Version:` header (and `ROLE_VERSION` if capabilities
changed), commit, then push a matching tag:

```bash
git tag 1.6.2 && git push origin 1.6.2
```

## Updating permissions later

1. Edit the `capabilities()` array in `jarvis-agent-role.php`.
2. Bump `ROLE_VERSION` **and** the `Version:` header.
3. Commit + push a matching tag. The role re-syncs on the next admin load, or force it
   with `wp jarvis sync`.

## Deactivation & uninstall

Deactivation removes the role and resets the version marker; users on the role fall back
to **no role** — reassign them first on a live site. The agent user (and its application
passwords) is intentionally left intact on deactivation, so a simple toggle never breaks a
live integration.

## License

GPL-2.0-or-later.
