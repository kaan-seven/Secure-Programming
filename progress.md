# Checkpoint 2 — Progress Note

## Implemented

- C++17 application using libsodium on Ubuntu/WSL.
- Hidden master-passphrase and account-password input.
- Encrypted vault creation, saving, and reopening.
- Argon2id key derivation and secretbox authenticated encryption.
- Rejection of an incorrect master passphrase before entering the menu.
- Account addition, listing, masked viewing, and confirmed deletion.
- Record count, field length, file size, and format checks.
- Private vault directory and owner-only vault file permissions.
- Advisory session locking.
- Documented build, run, and test commands.
- Incremental local commits recording implementation stages.

## Automated tests run successfully

- Encryption/decryption round trip.
- Wrong key, modified ciphertext, modified nonce, and truncated
  ciphertext rejection.
- Encrypted file save/load and decryption with a newly derived key.
- Saved file permissions and rejection of unsafe permissions.
- Credential-record round trip and empty-vault support.
- Rejection of truncated records, trailing data, excessive record counts,
  and oversized fields.

## Manual checks completed

- Create a vault, exit, and reopen with the correct passphrase.
- Reject a wrong master passphrase.
- Add an account and retain it after restarting.
- View account details without displaying the password.
- Reject an invalid menu selection.
- Cancel deletion, then confirm deletion and verify it after restarting.
- Check that the dummy account password does not appear as plaintext
  bytes in the saved vault.

## Limitations and remaining work

This is an educational prototype, not a production password manager.
Password retrieval/export and generation are not implemented.
There is no inactivity timeout, passphrase-change feature,
rollback detection, or secure backup system.
Memory clearing is best effort; input limits are checked after reading.
See README.md for additional limitations.

The application and all three automated test programs were rebuilt
successfully, and all automated tests passed in the configured Ubuntu/WSL
environment. A separate clean-machine test has not been performed.

Uploading the completed local commits to GitHub is the remaining step.
