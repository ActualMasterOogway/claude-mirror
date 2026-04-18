# Claude Mirror

A self-updating patched mirror of [Claude Code](https://github.com/anthropics/claude-code).

A GitHub Actions workflow polls the upstream GCS release channel every 15 minutes. When it sees a new version, it downloads every platform build (`linux-x64`, `linux-x64-musl`, `darwin-x64`, `win32-x64`), extracts the main module's JavaScript as `dumped.js` for easy reading, injects [`payload/rotate.js`](payload/rotate.js) into each binary's `.bun` section with [`scripts/bun_patcher.py`](scripts/bun_patcher.py), and publishes the result as a GitHub Release tagged `v{version}`. It then commits the new upstream version numbers to the repo's `latest` and `stable` text files so a patched client can find them.

The injected payload rewrites Claude Code's update-check URLs to point back at this repo, so a patched client keeps pulling patched updates. It also rotates across a comma-separated list of OAuth tokens in `CLAUDE_CODE_OAUTH_TOKEN` whenever the current one hits a quota wall or an auth failure.

## Repository layout

```
.
├── .github/workflows/mirror.yml   # The scheduled patch-and-release workflow
├── scripts/
│   ├── bun_patcher.py             # PE/ELF/Mach-O Bun standalone patcher
│   └── build_manifest.py          # Emits Claude Code manifest.json from a dir of patched bins
├── payload/
│   └── rotate.js                  # Injected runtime hook (mirror redirect + token rotation)
├── latest                         # Current upstream "latest" channel version (plain text)
├── stable                         # Current upstream "stable" channel version (plain text)
├── LICENSE
└── README.md
```

## How a patched client finds this mirror

Claude Code's updater fetches from:

```
{BASE}/latest                                    (plain-text version string)
{BASE}/stable                                    (plain-text version string)
{BASE}/{version}/manifest.json                   ({"platforms":{"<p>":{"checksum":"<sha256>"}}})
{BASE}/{version}/{platform}/claude[.exe]         (binary, SHA-256 verified against manifest)
```

`payload/rotate.js` hooks both Node's `https.request` and `globalThis.fetch`. When it sees a request for `storage.googleapis.com` on the upstream release path, it rewrites the URL to hit this repo instead:

| Upstream path                         | Rewritten to                                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------- |
| `{BASE}/latest`, `{BASE}/stable`      | `raw.githubusercontent.com/OWNER/REPO/main/<file>`                                    |
| `{BASE}/{ver}/manifest.json`          | `github.com/OWNER/REPO/releases/download/v{ver}/manifest.json`                        |
| `{BASE}/{ver}/{plat}/claude[.exe]`    | `github.com/OWNER/REPO/releases/download/v{ver}/{plat}-claude[.exe]`                  |

GitHub release downloads 302 to `objects.githubusercontent.com`. Both `axios` (Claude Code's updater) and Bun's native `fetch` follow redirects by default, so the extra hop doesn't need special handling.

## Running the pipeline

### Scheduled

The workflow runs on `cron: '*/15 * * * *'`. Each run fetches `{UPSTREAM}/latest`, checks whether a release with that tag already exists, and exits early if so. No new version means no work.

### Manual

Use the Run workflow button on the Actions tab. The `force_version` input rebuilds a specific version (e.g. `2.1.101`) even when its release already exists, which is what you want after changing the payload. Rebuilding an existing tag will fail unless you delete the release first (`gh release delete v2.1.101 --cleanup-tag`).

## Payload

`payload/rotate.js` is injected verbatim into the main module of each binary's `.bun` section. It's pure JS wrapping `https.request` and `globalThis.fetch`, and it runs before any Claude Code module can make a network call.

### Mirror redirect

Always active. Rewrites the three URL shapes listed above and logs every redirect to `~/.claude/tok-rot.log`.

### Token rotation

Active only when `CLAUDE_CODE_OAUTH_TOKEN` contains two or more comma-separated tokens:

```
export CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-AAA...,sk-ant-oat01-BBB...,sk-ant-oat01-CCC..."
```

On any Anthropic `/v1/messages` response that looks like quota or auth exhaustion (429/401/400/403 without a `retry-after`, `OAuth authentication is currently not allowed`, `out_of_credits` overage status, and so on), the payload advances to the next token and retries the request. Up to 15 rotations per request.

The current token is injected into outgoing requests as `Authorization: Bearer <token>`, so Claude Code's own auth path stays untouched.

## The patcher

`scripts/bun_patcher.py` handles Bun standalone binaries across all three executable formats:

- PE (Windows): writes into the `.bun` section and rewrites `VirtualSize` / `SizeOfRawData` / `SizeOfImage`. Clears the signature directory so the modified binary still loads.
- ELF (Linux): adjusts the `.bun` section and its owning `PT_LOAD` segment.
- Mach-O (macOS): expands the `__BUN` segment's `__bun` section.

After injection it rewrites the Bun-specific `Offsets` struct (total byte count, module-graph offset, argv offset) and every `StringPointer` in the module graph, so the runtime doesn't read stale offsets.

The docstring at the top of `scripts/bun_patcher.py` has the byte-level details.

## Using a patched binary

1. Grab the binary for your platform from the latest release.
2. Put it somewhere on your `PATH` (rename to `claude` / `claude.exe` if your shell cares).
3. Run it. First launch logs `[mirror] ACTIVE` to `~/.claude/tok-rot.log`.
4. Optional: set `CLAUDE_CODE_OAUTH_TOKEN` to a comma-separated token list to enable rotation.
5. Optional: set `DISABLE_AUTOUPDATER=1` to freeze the version instead of pulling patched updates from this mirror.

## Release assets

Each release under `v{version}` contains:

- `{platform}-claude` (or `claude.exe` for `win32-x64`) — the patched binary for each platform, with `payload/rotate.js` injected.
- `manifest.json` — SHA-256 checksums keyed by platform, in the shape Claude Code's updater expects.
- `dumped.js` — the main module's JavaScript source, extracted straight out of the upstream binary (before patching). Useful for reading what a given version actually ships.

## Development

Test the patcher locally against an upstream binary:

```bash
BASE="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases"
VER=$(curl -fsSL "$BASE/latest")
curl -fsSL -o claude-linux "$BASE/$VER/linux-x64/claude"

python scripts/bun_patcher.py patch claude-linux --inject payload/rotate.js -o claude-patched
./claude-patched --help
```

Dry-run the section rewrites without writing:

```bash
python scripts/bun_patcher.py patch claude-linux --inject payload/rotate.js --dry-run
```

Extract a binary's main-module JS (what gets uploaded as `dumped.js`):

```bash
python scripts/bun_patcher.py extract claude-linux dumped.js
```

## Legal

Mirrored binaries are derivative works of Claude Code. Anthropic's Terms of Service still apply; using this repo doesn't opt you out of them. This repository's own code is MIT-licensed — see `LICENSE`.
