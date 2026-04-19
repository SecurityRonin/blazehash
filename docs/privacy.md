# Privacy Policy

**Effective date:** 2026-04-19  
**Product:** blazehash CLI  
**Operator:** Security Ronin Ltd

---

## What blazehash collects

blazehash is a local command-line tool. It does not operate a server, does not have a backend, and does not transmit data to Security Ronin or any third party.

The only external service blazehash contacts is **Google's OAuth 2.0 endpoint** — and only when you explicitly run `blazehash gdrive auth login` or `blazehash gdrive-collect` with a Google Drive URL.

---

## Google OAuth token

When you authenticate with Google Drive:

- blazehash opens your browser to Google's consent screen.
- Google returns an OAuth access/refresh token directly to a local HTTP listener on `localhost`.
- The token is saved to **your local machine only**: `~/.config/blazehash/gdrive_token.json`.
- The token is **never transmitted to Security Ronin or any blazehash server** — no such server exists.
- The token grants blazehash the `drive.readonly` scope: read-only access to files you explicitly choose to hash. blazehash never writes to your Drive.

To revoke access at any time, visit [myaccount.google.com/permissions](https://myaccount.google.com/permissions) and remove blazehash, or delete `~/.config/blazehash/gdrive_token.json` locally.

---

## File data

blazehash reads files to compute cryptographic hashes. It does not upload file content anywhere. Hash values (e.g. SHA-256 digests) remain on your machine in the manifest files you create.

---

## Telemetry

blazehash has no telemetry, no crash reporting, no analytics, and no update checks. It never phones home.

---

## Open source

blazehash is fully open source under the MIT licence. You can audit every network call at [github.com/SecurityRonin/blazehash](https://github.com/SecurityRonin/blazehash).

---

## Changes

If this policy changes materially, the effective date above will be updated and a note will appear in the release changelog.

---

## Contact

Security Ronin Ltd — [github.com/SecurityRonin](https://github.com/SecurityRonin)
