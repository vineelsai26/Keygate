# Keygate

Keygate is a native macOS SSH key manager for app-owned keys, per-app access
rules, Touch ID/password approval, and CloudKit-backed metadata uploads.

It is intentionally shaped like an SSH agent. The app exposes a Unix-domain
socket and clients use it through `SSH_AUTH_SOCK` or OpenSSH `IdentityAgent`.
Private key material never leaves Keygate through the agent socket; clients
can list public identities and ask Keygate to sign payloads. An explicit,
Touch ID-gated export path exists for moving a key elsewhere.

## Status

- Key generation and signing for **Ed25519, ECDSA (nistp256/384/521), and RSA
  (2048/3072/4096)** through CryptoKit and the Security framework.
- **Import** of existing private keys from paste, file, or drag-and-drop:
  OpenSSH (`openssh-key-v1`, incl. bcrypt-encrypted) and PEM
  (PKCS#8/PKCS#1/SEC1, incl. PBES2-encrypted, incl. Ed25519 PKCS#8).
- **Export** of private keys (Touch ID gated): OpenSSH (optionally
  bcrypt+aes256-ctr passphrase-encrypted), PKCS#8, and PKCS#1 (RSA), to
  clipboard or `0600` file.
- Key management: rename, delete, per-key iCloud sync toggle, and
  `authorized_keys` export.
- Private key storage in owner-only (`0600`) files under
  `~/Library/Application Support/Keygate/keys`, gated for use by an in-app Touch
  ID/password prompt. Keys created by older builds are migrated out of the
  Keychain automatically on first use.
- RFC 9987 identity and sign-request handling.
- Policy engine for signed app, key, allow, deny, ask, and Touch ID/password
  rules.
- SwiftUI menu-bar app built on the shared `macos/vkit` design system: an
  always-visible status band over Keys / Policy / Activity / Setup tabs.
- Settings (⌘,): launch at login (via `SMAppService`), auto-start the agent,
  start in / close to the menu bar, Dock-icon visibility, and auto-lock on sleep.
- CLI for setup snippets, key generation/import/management, listing, and
  diagnostics.
- CloudKit account/status plumbing and opt-in public-key metadata uploads only;
  rules and audit history remain local. Ad-hoc builds without iCloud
  entitlements fall back to local-only operation.

Process identity includes team ID, signing identifier, and code hash when
macOS can validate the requesting executable's signature. CLI requests spawned
by nested app helpers are attributed to the outer owning application, so a rule
for Visual Studio Code also covers SSH launched by Code Helper.

### Third-party code

`Sources/CBcryptPBKDF` vendors OpenBSD's `bcrypt_pbkdf` (© 2013 Ted Unangst,
ISC) and Blowfish (© 1997 Niels Provos, BSD 3-clause), used only to decrypt
encrypted `openssh-key-v1` files. SHA-512 preprocessing is adapted to
CommonCrypto. Original copyright notices are retained in the source files.

## Build

```sh
make selftest
make app
make cli
```

### Code signing (Touch ID)

`make app`/`make cli` sign with a local identity named **Keygate Local Signing**
when one exists in the login keychain, falling back to ad-hoc signing otherwise.
A stable identity matters for two reasons: the Keychain "always allow" grant then
persists across rebuilds (ad-hoc signatures change every build, so the Keychain
re-prompts), and it lets the app launch with the local entitlements.

Create the identity once via Keychain Access → Certificate Assistant → *Create a
Certificate*: name `Keygate Local Signing`, identity type *Self-Signed Root*,
certificate type *Code Signing*. The self-signed identity is signed with the
local (`entitlements-local.plist`) profile, which omits the restricted iCloud
entitlements a self-signed cert cannot carry (CloudKit stays local-only).

## Run

Start `dist/Keygate.app`, then either opt into Keygate for one shell:

```sh
export SSH_AUTH_SOCK="/tmp/keygate-$(id -u)/agent.sock"
```

or add this to `~/.ssh/config`:

```sshconfig
Host *
  IdentityAgent /tmp/keygate-501/agent.sock
```

Use the CLI to print the exact snippets for the current user:

```sh
dist/keygate install-snippet
```

## CLI

```sh
keygate socket
keygate env
keygate ssh-config
keygate generate "GitHub personal"                 # Ed25519 by default
keygate generate --type ecdsa-p256 "Work laptop"    # or rsa, ecdsa-p384, ecdsa-p521
keygate generate --type rsa --bits 4096 "Legacy CI"  # RSA 2048/3072 (default)/4096
keygate import ~/.ssh/id_rsa                         # OpenSSH or PEM
keygate import ~/.ssh/id_ed25519 --passphrase-env KEYPASS
keygate list
keygate pub <fingerprint>                            # authorized_keys line
keygate export <fingerprint> --output backup.key     # OpenSSH by default
keygate export <fingerprint> --format pkcs8          # or pkcs1 (RSA)
keygate export <fingerprint> --passphrase-env KEYPASS # encrypted OpenSSH
keygate rename <fingerprint> "New label"
keygate delete <fingerprint>
keygate diagnose
```

## Security Model

- Unknown apps require user presence by default.
- Rules may always allow, ask every time, allow for a duration, deny, or require
  user presence.
- Agent forwarding fails closed: Keygate rejects OpenSSH session bindings until
  it can verify and enforce the complete binding protocol. Destination-scoped
  rules are therefore not exposed in the UI.
- Private key bytes are stored in owner-only (`0600`) files under
  `~/Library/Application Support/Keygate/keys`; metadata (public keys, comments)
  lives in local JSON. Keys are deliberately *not* in the macOS Keychain:
  Keychain items bind to the creating binary's code signature, so a
  locally/self-signed build that is rebuilt often is treated as a new app and
  re-prompts for the login password on every use.
- Optional passphrase encryption at rest: enabling it (app "Encrypt Keys…" or
  `keygate encrypt`) seals each key file with AES-256-GCM under a key derived
  from your passphrase via PBKDF2-HMAC-SHA256 (600k iterations). The passphrase
  and derived key never touch disk or the Keychain; the key is cached in memory
  for the session. Unlock once per app launch (`KEYGATE_PASSPHRASE` for scripts).
  Secure Enclave was evaluated but needs an entitlement a self-signed build can't
  carry, so passphrase encryption is the at-rest option here.
- Signing decisions of `requireUserPresence`, `askEveryTime`, and (on first use
  per window) `allowForDuration` prompt for Touch ID/password through
  LocalAuthentication before the key file is read. Because this gate is in the
  app rather than the Keychain, biometric approval works on ad-hoc and
  self-signed builds and does not depend on code-signing stability.
- Private key export prompts for Touch ID/password before revealing key material
  and never leaves through the agent socket.
- Trade-off: without passphrase encryption enabled, at-rest protection is
  filesystem permissions only (like plain `~/.ssh` keys). Enabling passphrase
  encryption adds AES-256-GCM at rest at the cost of an unlock per session.

## Project Layout

```text
Package.swift
Sources/
  KeygateCore/        # SSH agent protocol, signing, vault, import, policy, sync
  CBcryptPBKDF/       # vendored OpenBSD bcrypt_pbkdf (encrypted OpenSSH import)
  KeygateApp/         # SwiftUI menu-bar app
  keygate-cli/        # command-line setup, key management, and diagnostics
  keygate-selftest/   # no-XCTest test runner
Resources/            # Info.plist and entitlements
```
