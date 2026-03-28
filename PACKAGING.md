# blazehash Distribution & Packaging

## Automated (on every tagged release)

### Homebrew (macOS / Linux)

**Status:** Automated via `repository-dispatch` to [SecurityRonin/homebrew-blazehash](https://github.com/SecurityRonin/homebrew-blazehash).

```
brew tap SecurityRonin/blazehash
brew install blazehash
```

When a `v*` tag is pushed, the release workflow dispatches to the Homebrew tap repo, which downloads the new release assets and updates the formula SHA256 hashes automatically.

**Required secret:** `TAP_GITHUB_TOKEN` (PAT with `repo` scope on the tap repo).

### Winget (Windows)

**Status:** Automated via [`vedantmgoyal9/winget-releaser@v2`](https://github.com/vedantmgoyal9/winget-releaser).

```
winget install SecurityRonin.blazehash
```

On each release, the `winget` job auto-creates a PR to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) with the updated manifest pointing to the Windows `.zip` asset.

**Required secret:** `WINGET_TOKEN` (GitHub PAT with `public_repo` scope — needed to fork and PR against winget-pkgs).

**First-time setup:** The initial winget-pkgs submission requires a manually created PR with the full package manifest (version, installer URL, SHA256, license, description). After the first version is merged, `winget-releaser` handles all subsequent updates automatically.

### Debian packages (.deb)

**Status:** Automated builds via `cargo-deb`. Packages are uploaded as GitHub release assets.

```
# Download from GitHub releases
curl -LO https://github.com/SecurityRonin/blazehash/releases/latest/download/blazehash_<version>_amd64.deb
sudo dpkg -i blazehash_<version>_amd64.deb
```

Architectures built: `amd64` (x86_64) and `arm64` (aarch64).

## Manual / Future

### Official Debian repository

Getting into the official Debian archive makes the package available to Debian, Ubuntu, Kali, and all downstream distributions automatically.

**Process:**

1. **File an ITP (Intent to Package) bug** against the `wnpp` pseudo-package on [bugs.debian.org](https://bugs.debian.org). This is the formal declaration that you intend to package blazehash for Debian.

2. **Find or become a Debian maintainer.** Packages need a Debian Developer (DD) or Debian Maintainer (DM) to sponsor the upload. Options:
   - Join the [Debian Forensics Team](https://wiki.debian.org/Teams/Forensics) (blazehash fits this team's scope)
   - Find a sponsor on [mentors.debian.net](https://mentors.debian.net)

3. **Create Debian packaging files** (`debian/` directory):
   - `debian/control` — package metadata, build-deps
   - `debian/rules` — build recipe (for Rust: use `dh-cargo`)
   - `debian/copyright` — DEP-5 machine-readable format
   - `debian/changelog` — Debian changelog format
   - `debian/watch` — upstream release monitoring

4. **Upload to mentors.debian.net** for sponsor review. After sponsor approval, the package enters Debian `unstable`.

5. **Migration path:** `unstable` -> `testing` -> `stable` (automatic after ~10 days with no RC bugs).

**Timeline:** The ITP + sponsorship + review process typically takes weeks to months depending on sponsor availability and package quality. Once in Debian, all downstream distributions (Ubuntu, Kali, etc.) inherit it automatically.

### Kali Linux (fast-track)

Kali maintains its own package repository and accepts tool submissions independently of Debian.

**Process:**

1. **Submit a tool addition request** via the [Kali Bug Tracker](https://bugs.kali.org) under the "New Tool Requests" category.

2. **Required information:**
   - Tool name, homepage, description
   - Why it's useful for penetration testing / forensics
   - Existing packaging (link to .deb or Debian ITP)

3. **Kali packaging:** If accepted, the Kali team creates a packaging repo on [GitLab (kali-team)](https://gitlab.com/kalilinux/packages/). They may ask the author to help with packaging.

4. **blazehash's case:** As a forensics tool that replaces/extends hashdeep (already in Kali), blazehash is a strong candidate. The existing `.deb` builds from our release pipeline simplify the packaging effort.

### Ubuntu PPA (alternative to waiting for Debian)

If the official Debian process is too slow, a PPA provides immediate access for Ubuntu users.

1. Create a Launchpad account and PPA
2. Upload source packages signed with a GPG key registered on Launchpad
3. Users add the PPA:
   ```
   sudo add-apt-repository ppa:securityronin/blazehash
   sudo apt update && sudo apt install blazehash
   ```

**Trade-off:** PPAs require ongoing manual maintenance for each Ubuntu release. The official Debian route is preferred long-term.

## Secret Configuration Summary

| Secret | Purpose | Scope |
|--------|---------|-------|
| `TAP_GITHUB_TOKEN` | Dispatch to Homebrew tap repo | `repo` on SecurityRonin/homebrew-blazehash |
| `WINGET_TOKEN` | PR to microsoft/winget-pkgs | `public_repo` |
