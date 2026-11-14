# Guest Accounts for Silo

Time-limited Silo accounts. Give someone access for a set number of days (or
until a date), and when the time is up the plugin disables the account, which
signs it out of every app and device. The same page manages which libraries
each account can see.

Plugin id `beisem.guest-accounts`. Adds **Guest accounts** to the admin menu.
Linux amd64 and arm64.

## What it does

- **New guest**: creates a Silo account with a username, email, password
  (or a generated one, shown once), an optional forced password change, a
  profile, its libraries and an expiry. Offline downloads and requests are
  off unless you allow them (see below for why).
- **Expiry on any account**: set, extend or remove the expiry on any existing
  non-admin account. "Extend by" adds to the current expiry, or to now if it
  has already passed.
- **When access ends** the account is disabled. Optionally it is deleted a
  set number of days later (off by default; deleting removes its profiles and
  watch history).
- **Extending an expired account** turns it back on (a setting, on by
  default), but only if the plugin is what disabled it. An account an admin
  disabled stays off.
- **Turned back on by hand?** If you re-enable an expired account in Silo
  yourself, the plugin respects that and won't disable it again until you give
  it a new expiry. It won't delete it either.
- **Libraries**: all libraries (or the access group's), exactly the libraries
  you tick, or none. Optionally move the account into an access group.
- **Presets**: named library selections for the combinations you use often.
- **Activity log** of everything the plugin changed, and by whom.

## Install

1. In Silo, go to **Settings → API keys** and create a key with the
   `admin:users` scope. Add `admin:access-groups:read` too if you want to
   pick access groups on the plugin's page. The key's owner must be an admin.
2. Download `guest-accounts-linux-amd64` (or `-arm64` on ARM) from the latest
   [release](../../releases/latest) and check it against `checksums.txt`.
3. In Silo, go to **Admin → Plugins → Upload** and upload it.
4. Open the plugin's settings and paste the key into **Silo connection**.
5. In **Scheduled Tasks**, give **Guest accounts: expire accounts** a
   15-minute interval. The plugin also checks every 5 minutes on its own while
   it runs; the task is the safety net, and it starts the plugin after a
   restart.

Uploading a newer binary with the same plugin id keeps its settings, expiry
dates, presets and log.

## How it talks to Silo

Plugins can't manage accounts through the plugin host (`RuntimeHost` has no
user operations), so this plugin uses Silo's admin REST API with the scoped
key, the same way Email Alerts reads the catalog:

| Call | Used for |
|---|---|
| `GET /api/v2/admin/users` | The account list (paged, 200 at a time) |
| `GET /api/v2/admin/users/{id}` | Reading an account and its ETag |
| `PUT /api/v2/admin/users/{id}` + `If-Match` | `enabled`, `library_ids`, `access_group_id` |
| `POST /api/v2/admin/users` | Creating a guest |
| `DELETE /api/v2/admin/users/{id}` + `If-Match` | Deleting (by hand, or after the grace period) |
| `GET /api/v2/admin/access-groups` | Group names for the pickers (optional scope) |
| Host `ListLibraries` | Library names and ids |

Every write reads the account first for its ETag and retries once on `412`.
Setting `enabled: false` makes Silo sign the account out everywhere (login,
Jellyfin- and Audiobookshelf-compatible sessions). Library changes don't
sign anyone out; Silo applies them on the account's next request.

## Security

- **Admins are never touched.** The plugin refuses to change or expire an
  admin account or the Owner, and an `admin:users` key can't anyway. Every
  write carries the account's ETag, so an account promoted to admin between
  the check and the write is refused by Silo (412) rather than changed.
- **Only admins reach the API.** Silo routes `/api/admin/*` only for admin
  sessions, stamps `X-Silo-User-Role` itself and drops any `X-Silo-*` header
  a browser sends; the plugin also refuses a non-admin role header.
- **CSRF.** Silo's plugin cookie is `SameSite=Lax`, which blocks cross-site
  POSTs but not ones from another subdomain of the same site. Every change
  must be sent as `application/json` (415 otherwise): an HTML form can't send
  that, and a cross-origin `fetch` that does needs a CORS preflight Silo
  doesn't grant.
- **XSS.** Everything from Silo is escaped before it is rendered, and the page
  carries a Content-Security-Policy that only allows its own script (by hash)
  and requests to its own origin.
- **The API key** is stored encrypted by Silo and only sent to Silo's own
  listener. Scope it to `admin:users` (+ `admin:access-groups:read`). If the
  key is deleted, or its owner is disabled or demoted, expiry stops working:
  the page shows a red banner and the scheduled task reports the error.
- **Passwords** are never logged or stored by the plugin. A generated one is
  returned once, with `Cache-Control: no-store`.
- **Account ids** only ever grow in Silo, so an expiry for a deleted account
  can never land on a new one.

## What expiry does not cover

- **Offline downloads.** Silo downloads have no DRM, expiry or lease: files
  already on a device keep playing after the account is disabled, and a
  disabled account never syncs, so revoking them doesn't reach the device.
  New guests are therefore created with **downloads off** (and **requests
  off**) unless you tick otherwise; the page flags timed accounts that can
  download.
- **Expiry needs the plugin running.** If the plugin is stopped, accounts stay
  active until it starts again (the scheduled task starts it).
- **Expiry dates live in the plugin's encrypted instance state**, not on the
  Silo account. Uninstalling the plugin (or wiping its state) loses them;
  re-uploading the same `plugin_id` keeps them.
- **Silo's own audit log** shows changes as made by the API key's owner; the
  plugin's Activity tab records which admin actually made them.

## Library ids

An account's `library_ids` is `null` for "inherit" (every library, or its
access group's), `[]` for none, and a list for exactly those. The plugin sends
`null` for **All libraries** and the ticked ids otherwise, so ticking nothing
really does mean no libraries.

## Files

| File | What it does |
|---|---|
| `main.go` | Serves the plugin (scheduled task + HTTP routes) |
| `config.go` | Parses the Silo connection settings |
| `silo.go` | Admin REST client: accounts, ETags, access groups, pacing and 429 handling |
| `store.go` | Settings, expiry grants, presets and the log in instance state |
| `engine.go` | The expiry check, the 5-minute timer and the scheduled task |
| `http.go` | Admin API behind `/api/admin/*`, the page and its CSP |
| `web/admin.html` | The admin page (vanilla JS, embedded) |
| `engine_test.go` | Tests against a fake Silo admin API with ETags |

## Build

Needs Go 1.26+.

```sh
make test
make build    # dist/guest-accounts-linux-amd64 and -arm64
```

## Releasing

Bump `version` in `manifest.json` and `VERSION` in the `Makefile`, then push
to `main`. The release workflow tests, builds both architectures and publishes
a `v<version>` release with the binaries and `checksums.txt`.

## License

MIT. See [LICENSE](LICENSE).
