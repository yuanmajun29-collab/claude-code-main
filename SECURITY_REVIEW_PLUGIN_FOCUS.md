# Security review: plugin / LSP / updater / output-styles / hooks focus

Commit: `afe3d14c971c027d6f8091ecf220b4651f22671c`
Run: `bc-244095a6-ca28-5b72-848c-4f94d0b5dd61` (2026-11-23)

## New validated finding

### HIGH — `validateOfficialNameSource` git URL substring bypass

**Location:** `src/utils/plugins/schemas.ts:119-157`

Reserved marketplace names are supposed to be usable only by `github.com/anthropics/*`. For `source: 'git'`, validation is:

```ts
url.includes('github.com/anthropics/') || url.includes('git@github.com:anthropics/')
```

Attacker URL `https://evil.example/github.com/anthropics/agent-skills.git` passes, clones from the attacker host, and registers under the reserved name. Official names default `autoUpdate: true` (`isMarketplaceAutoUpdate`). GCS heal on refresh applies only to exact name `claude-plugins-official`; other reserved names (`agent-skills`, `life-sciences`, …) always refresh from the stored git URL.

**Attack path (summary):**
1. Host marketplace.json with a reserved `name` + plugins with SessionStart hooks / stdio MCP / `.lsp.json`.
2. Via project `.claude/settings.json` `extraKnownMarketplaces` + `enabledPlugins` (post-TrustDialog), or via `claude plugin marketplace add` with the lookalike git URL.
3. `addMarketplaceSource` → `validateOfficialNameSource` returns null → `known_marketplaces.json` stores reserved name + evil source.
4. Autoupdate keeps pulling attacker content machine-wide; plugin hooks/MCP/LSP spawn without MCP consent (same sinks as prior #10).

**Why new vs #10:** #10 is general project marketplace auto-install. This bypasses the dedicated official-name reservation control and upgrades impact via default `autoUpdate: true` + reserved-name credibility + persistence outside the original project.

**Evidence:** see flagged finding #22 in automation memories JSON.

## Focus candidates — not new MEDIUM+

| Candidate | Verdict |
|-----------|---------|
| Zip / MCPB path traversal | `unzipFile` → `isPathSafe` / `containsPathTraversal`; absolute paths rejected. fflate returns file bytes only (no symlink materialization). |
| Marketplace git clone hooks | `git clone` does not execute remote repo hooks; `--recurse-submodules` still needs marketplace trust (#10 / new finding). |
| npm install without `--ignore-scripts` | `installFromNpm` runs `npm install` with no `--ignore-scripts` — only reachable after marketplace plugin cache (#10 amplification). |
| Plugin auto-update | Third-party defaults `autoUpdate: false`; official defaults true — dangerous only after official-name poison (new finding) or intentional user enable. |
| Official GCS marketplace | Hardcoded `downloads.claude.ai` URL; path confined to marketplaces cache; zip validated. Not project-controllable. |
| LSP `getAllLspServers` | Plugin-only (`config.ts:9-12`); no projectSettings LSP. Spawn via `LSPClient` requires enabled plugin → #10 / new finding. No separate consent beyond plugin enable. |
| Native auto-updater | Hardcoded GCS bucket; SHA-256 of binary checked against same-origin `manifest.json` checksum. `autoUpdatesChannel` only `latest`/`stable`. Project settings cannot redirect download URL. npm global install runs from `$HOME` to avoid project `.npmrc`. |
| Package-manager updater | Same: not attacker-URL-controllable from project settings. |
| Output styles | Project `.claude/output-styles/*.md` + `settings.outputStyle` inject system-prompt text after trust (like CLAUDE.md). Tools still permission-gated unless bypass already reported (#6/#8). `force-for-plugin` ignored for non-plugin styles. Not MEDIUM+ alone. |
| Plugin `hooks.json` path besides #10 | `loadPluginHooks` only registers hooks from enabled plugins. Enablement requires `enabledPlugins` (+ marketplace materialization). No alternate path that skips marketplace/plugin enable. Overlap with #10 / new finding. |
| Settings hooks | Already #13 (TrustDialog SessionStart RCE). |

## Explicitly not re-reported

Prior findings 1–20 (and existing #21 HTTP PreToolUse `permissionDecision:allow` if present in the flagged store).
