# SECURITY GATE — Tauri Signing Key Leak

## STATUS: SECURITY BLOCKER — HISTORY PURGE + KEY ROTATION REQUIRED

A Tauri code-signing private key was committed to the git repository in history.
Although the key files were later deleted from the working tree and added to
`.gitignore`, the git **history** still contains the leaked credentials.

This is a release blocker for NSIS/MSI production builds (which require
code signing), but does NOT block the WireGuard runtime itself.

---

## 1. AFFECTED COMMITS

| Commit | Short Hash | Message | Action |
|--------|------------|---------|--------|
| `0a7456b` | `0a7456b` | `fix: bug clippy v4` | **ADDED** `tauri.key` + `tauri.key.pub` |
| `7f0a206` | `7f0a206` | `fix: bug clippy v3` | **PREDECESSOR** of `0a7456b` (contains key in working tree) |
| `b481f4b` | `b481f4b` | `Fix WireGuard NT 1.1 runtime and release packaging` | DELETED key files, added `.gitignore` |

**Leaked file paths (all 4 variants were committed):**

```
tauri.key                 — committed in 0a7456b
tauri.key.pub             — committed in 0a7456b
src-tauri/tauri.key       — committed in 0a7456b
src-tauri/tauri.key.pub   — committed in 0a7456b
```

## 2. AFFECTED REFS

The commit `0a7456b` is an ancestor of ALL current refs:

```
$ git merge-base --is-ancestor 0a7456b ebc890a  → YES (HEAD / v0.1.3)
$ git merge-base --is-ancestor 0a7456b fd96d2b  → YES (main)
$ git merge-base --is-ancestor 0a7456b 12ba6e8  → YES (origin/main)
```

**Affected refs that must be rewritten:**

| Ref | Type | Current tip | Contains leaked key? |
|-----|------|-------------|---------------------|
| `main` (fd96d2b) | Local branch | `fd96d2b` | ✅ YES |
| `main` (12ba6e8) | Remote branch | `12ba6e8` | ✅ YES |
| `fix/wireguard-nt-1.1-runtime` | Tag | `ebc890a` | ✅ YES |
| `v0.1.3` | Tag | `ebc890a` | ✅ YES |
| `main` (tag at 56ad661) | Tag | `56ad661` | ✅ YES |

All refs contain the leaked key in their history.

## 3. LEAKED CONTENT (Verified)

`tauri.key` was a rsign (minisign) encrypted secret key:
```
untrusted comment: rsign encrypted secret key
RWRTY0Iy9K70vaQ{M1U+uG0FSSpyBe+uH37SY5CtgXacqxwgShMAAB...
```

`tauri.key.pub` was the matching minisign public key:
```
untrusted comment: minisign public key: 20C4BC57F92D53D2
RWTSUy35V7zEICury6+iOFogaBM6+vLPw7UiK9O48LkHJKyQhMcocDsx
```

The private key is encrypted but the passphrase may also have been stored
in CI environment or git, making it effectively compromised.

## 4. REQUIRED FILTER-REPO COMMAND

> ⚠️ **DO NOT execute this automatically.** Review with the team first.

```bash
# 1. Backup the repository
git clone --mirror https://github.com/beatzip/marstart-link.git marstart-link-backup.git
cd marstart-link-backup.git
git bundle create ../marstart-link-backup.bundle --all

# 2. Install git-filter-repo
pip install git-filter-repo

# 3. Return to the working repo
cd ..
cd marstart-link

# 4. Purge the leaked key files from all history
git filter-repo \
  --invert-paths \
  --path tauri.key \
  --path tauri.key.pub \
  --path src-tauri/tauri.key \
  --path src-tauri/tauri.key.pub \
  --force

# 5. Verify the key is no longer in history
git log --all --oneline -- tauri.key
git log --all --oneline -- src-tauri/tauri.key
# Should return NO results

# 6. Generate a NEW signing key pair
tauri signer generate --force

# 7. Store the private key ONLY in GitHub Secret: TAURI_PRIVATE_KEY
#    Store the passphrase in: TAURI_PRIVATE_KEY_PASSWORD
#    (Store the public key in the repo as tauri.key.pub)

# 8. Force-push ALL refs (requires team coordination)
git push --force-with-lease --all
git push --force-with-lease --tags

# 9. Re-tag v0.1.3 if it was lost in the rewrite
git tag -f v0.1.3 <new_commit_hash>
git push origin v0.1.3 --force
```

## 5. BACKUP PROCEDURE

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `git clone --mirror <url> repo-backup.git` | Full mirror backup |
| 2 | `cd repo-backup.git && git bundle create ../backup.bundle --all` | Bundle all refs |
| 3 | Verify bundle: `git bundle verify ../backup.bundle` | Confirm backup integrity |
| 4 | Store backup on isolated, offline storage | Prevent data loss |

## 6. FORCE-PUSH IMPLICATIONS

| Stakeholder | Impact | Mitigation |
|-------------|--------|------------|
| All contributors | Local clones become stale | `git fetch --all && git reset --hard origin/main` |
| CI/CD pipelines | References old commit hashes | CI auto-triggers on new push |
| Issue/PR references | Commit hashes in comments broken | GitHub auto-redirects (best-effort) |
| Release tags | `v0.1.3` tag points to old history | Re-tag after purge |
| Forks | Diverge from upstream | Forks must re-sync manually |

**Coordination protocol:**
1. Announce purge window on team chat
2. Block all merges during purge
3. After force-push, all contributors run:
   ```
   git fetch --all
   git checkout main
   git reset --hard origin/main
   ```

## 7. KEY ROTATION PROCEDURE

### Step 1: Retire old key
The old key (minisign public key `20C4BC57F92D53D2`) is considered compromised.
Treat all binaries signed with it as untrusted.

### Step 2: Generate new keypair
```bash
# On a secure, air-gapped machine
tauri signer generate --force
# Output:
#   tauri.key          (private — store ONLY in GitHub Secret)
#   tauri.key.pub      (public — can be committed)
```

### Step 3: Store private key in GitHub
```bash
# Base64-encode the private key for GitHub Secret
base64 -w0 tauri.key
# Add to GitHub: Settings → Secrets → Actions → TAURI_PRIVATE_KEY
```

### Step 4: Commit public key
```bash
git add tauri.key.pub
# .gitignore should still exclude tauri.key
git commit -m "chore: rotate Tauri signing key — new public key"
```

### Step 5: Rebuild + sign installers
```bash
npm run tauri build
# CI will sign with new key
```

### Step 6: Verify signatures
```powershell
# Verify NSIS
Get-AuthenticodeSignature marstart-link_0.1.1_x64-setup.exe
# Verify MSI
Get-AuthenticodeSignature marstart-link_0.1.1_x64.msi
# Verify EXE
Get-AuthenticodeSignature marstart-link.exe
```

## 8. RELEASE IMPACT

| Item | Impact | Status |
|------|--------|--------|
| WireGuard runtime | ❌ NOT affected | ✅ Code is clean |
| EXE manifest (requireAdministrator) | ❌ NOT affected | ✅ Verified via mt.exe |
| wireguard.dll | ❌ NOT affected | ✅ No secrets in binary |
| NSIS installer | ⚠️ Cannot sign (key rotated) | ⛔ BLOCKED until key rotated |
| MSI installer | ⚠️ Cannot sign (key rotated) | ⛔ BLOCKED until key rotated |
| AppX/MSIX | ⚠️ Cannot sign (key rotated) | ⛔ BLOCKED until key rotated |
| GitHub Releases | ⚠️ Cannot publish signed binaries | ⛔ BLOCKED until key rotated |
| Auto-update | ⚠️ Signatures will fail | ⛔ BLOCKED until key rotated |

## 9. VERIFICATION PROCEDURE

After purge + rotation:

```bash
# 1. Verify key is not in history (must return NO commits)
git log --all --oneline -- tauri.key
git log --all --oneline -- src-tauri/tauri.key
git log --all --oneline -- "*.key" "*.key.pub"

# 2. Verify key is not in working tree
git ls-files | grep -i tauri.key
# Should return nothing

# 3. Verify git history is clean
git fsck --full
git log --oneline -5

# 4. Verify new signing key works
npm run tauri build 2>&1 | grep -i "sign"
# Should show successful signing

# 5. Verify signed binary
signtool verify /pa /v target/release/bundle/nsis/*.exe
```

## 10. CURRENT STATUS

| Check | Result |
|-------|--------|
| Key in working tree? | ❌ No (deleted, in .gitignore) |
| Key in git history? | ✅ **YES — SECURITY BLOCKER** |
| Key rotated? | ❌ No |
| New key in GitHub Secrets? | ❓ Unknown (cannot verify from this environment) |
| CI workflow references secret? | ✅ Yes (`secrets.TAURI_PRIVATE_KEY`) |

**The WireGuard runtime code is secure. The signing key rotation is a release-process issue only.**
