# Jarvis Agent Role

A self-contained plugin that defines the `jarvis_agent` WordPress role for the AI agent user.
Capabilities are version-controlled in code — the role re-syncs whenever the version constant
bumps, so updating permissions never requires deactivating/reactivating.

## Why a role (not just a user)

Permissions live on the **role**, so you grant/revoke once and every Jarvis user inherits it.
The cap list in `jarvis-agent-role.php` (`capabilities()`) is the single source of truth.

## Custom post types — derived, not hand-listed

The Block MCP tools edit `post_content` on **any** post type (popups, EDD downloads, future
CPTs). Those CPTs register **custom capability types**, so generic `edit_posts` doesn't grant
edits to them. Rather than maintain a hand-list that rots, `derive_cpt_capabilities()` walks
`post`, `page`, and every `show_in_rest` post type and pulls each one's mapped
`edit_posts`/`edit_others_posts`/`edit_published_posts`/`publish_posts` cap names off its
capability object — so `popup` → `edit_popups`, `download` (capability_type `product`) →
`edit_products`, automatically and forever.

This mirrors the Block MCP plugin's own `Agent_Provisioner::derive_capabilities()`. Because
activation can run before EDD/Popup Maker register their CPTs, `maybe_sync_role()` re-asserts
any missing derived caps on every `admin_init` (cheap; only writes when a cap is actually
missing). New CPT appears → next admin load grants its caps. No version bump needed for that.

> **Relationship to `block_mcp_agent`:** the Block MCP plugin provisions its own
> `block_mcp_agent` role with the same derivation. We keep `jarvis_agent` **separate** (it
> also carries `manage_options`, FluentCRM, and FluentBoards caps the block role omits) but
> seed it from the same logic, so block coverage is native — no dependency on that role.

## Baseline: "Admin-minus"

Jarvis gets everything the MCP/REST tooling exercises, but **none** of the caps that allow
code execution or account escalation. Withheld on purpose (see the docblock in the plugin):

- `install_plugins`, `activate_plugins`, `edit_plugins`, `edit_themes`, `edit_files`
- `update_core`, `update_plugins`, `update_themes`
- `create_users`, `edit_users`, `delete_users`, `promote_users`
- `unfiltered_html`, `export`, `import`

A leaked credential can edit content and settings — it cannot run arbitrary PHP or escalate.

## Per-site provisioning

When grabbing the application password on a new site:

1. **Copy** this folder into `wp-content/plugins/` and activate it
   (or `wp plugin activate jarvis-agent-role`). **Activation does two things:**
   registers the `jarvis_agent` role, then **creates the `jarvis` user**
   (`jarvis@example.com`, display name "Jarvis") on that role if it doesn't
   already exist. Idempotent — re-activating won't duplicate or clobber.
2. **Generate an application password** (revocable, scoped to this user):
   ```bash
   wp user application-password create jarvis "jarvis-mcp" --porcelain
   ```
   Store the returned token in the MCP/agent config for that site. Rotate by deleting and
   re-creating the application password — never touches the role or other sites.

`wp jarvis user` re-runs the provisioning check on demand (and prints the app-password
command). Login/email are filterable: `jarvis_user_login`, `jarvis_user_email`.

The user is created (or adopted) with display name **and** nickname `Jarvis (AI Agent)`, a
**Biographical Info** bio (the `description` field — filterable via `jarvis_user_bio`), and a
bundled avatar (`assets/jarvis-avatar.png`) served locally for it everywhere WP renders an
avatar — admin user list, comments, block-editor author chip — bypassing Gravatar. Re-running
`wp jarvis user` re-asserts display name / nickname / bio on an existing agent account.

### Safety: account adoption rules

- A pre-existing account is **adopted** only when **both** the login *and* the email match the
  canonical agent identity and resolve to the same user (i.e. the account we'd have created
  ourselves — e.g. one made earlier via `wp user create`). It's then flagged, given the role,
  and its identity set.
- If only the login **or** the email collides with a *different* account, provisioning
  **refuses** — it won't bolt the agent role onto a real person's user. Pick a different
  login/email via the `jarvis_user_login` / `jarvis_user_email` filters, or flag the intended
  account manually (`wp user meta update <id> _jarvis_agent_user 1`) then run `wp jarvis user`.

## Distribution & updates (Git Updater)

This plugin is distributed from the private repo
[`code-atlantic/jarvis-agent-role`](https://github.com/code-atlantic/jarvis-agent-role) via
[Git Updater](https://git-updater.com/). The main file carries the required headers
(`GitHub Plugin URI`, `Primary Branch: main`). Any site with Git Updater installed and
authenticated with a GitHub token that can read the `code-atlantic` org will see new tagged
releases as ordinary plugin updates — no manual copying.

**Cutting a release:** bump `Version:` and `ROLE_VERSION` together, commit, then push a tag that
matches the version:

```bash
git tag 1.5.0 && git push origin 1.5.0
```

Git Updater reads the newest tag. On a private install the role still re-syncs on the next admin
load after the update (or run `wp jarvis sync`).

## Updating permissions later

1. Edit the `capabilities()` array in `jarvis-agent-role.php`.
2. Bump `ROLE_VERSION` **and** the `Version:` header to match.
3. Commit + push a matching tag. Sites pull it via Git Updater; the role re-syncs on the next
   admin load, or force it:
   ```bash
   wp jarvis sync
   ```

## Per-site overrides without forking

Use the `jarvis_role_capabilities` filter (e.g. in a site mu-plugin) to drop or add a cap on
one site — for example, revoking `manage_options` on a hardened install. Bump `ROLE_VERSION`
or run `wp jarvis sync` afterward so the change materializes.

## Audit log

Captured at the **Abilities API layer**, not via guessed core hooks. The Abilities API
fires `wp_before_execute_ability` / `wp_after_execute_ability` around *every* ability
execution, so this logs every MCP/agent tool call — our `mcp-adapters`, the core
`mcp-adapter`, FluentBoards/CRM adapters, and any custom tool added later — in one place,
touching zero core/vendor files. Auth events (cookie login + application-password) don't
run through an ability, so they're captured separately.

Logging fires **only** for `jarvis_agent` users — humans and other API clients log nothing.

Each `ability` entry records the **tool name and full input args**, plus an `ok`/`error`
status. Result bodies are **not** logged — a read tool's payload is noise, and for
write/delete/update tools the input args already capture what changed. On failure the
`WP_Error` code + message are kept ("it failed, and why" is signal). This is an internal-only
trail, so input values are logged in full — **except** credential-shaped keys (`password`,
`token`, `secret`, `app_password`, `api_key`, …), redacted even here so the log never becomes
a secret sink. Oversized inputs are clipped (20 KB) to keep lines sane.

### Location

Defaults to `jarvis-audit/jarvis-audit.log` **one level above `wp-content`** (typically above
the web root, so the trail isn't web-reachable) when that path is writable; otherwise falls
back to `wp-content/jarvis-audit.log`. Override explicitly:

```php
// wp-config.php
define( 'JARVIS_AUDIT_LOG_FILE', '/var/log/jarvis/audit.log' );
```

```bash
wp jarvis audit --lines=50      # last 50 events (prints the resolved path too)
tail -f "$(wp jarvis audit --lines=0 2>&1 | tail -1)"   # live
```

- Rotates at 10 MB (keeps one `.1` backup). Self-bounding; no cleanup needed.
- Writes fail silently by design — auditing never breaks the request it observes.
- **Not tamper-proof:** a `manage_options` credential could reach a log inside the tree.
  For a defensible trail, point `JARVIS_AUDIT_LOG_FILE` somewhere the web user can append
  but not read/rewrite, or ship lines to an external sink.

## Deactivation

Removes the role and resets the version marker. Users on the role fall back to **no role** —
reassign them before deactivating on a live site.
