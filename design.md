# Password Manager — Checkpoint 1 Design

## Scope

This is a planned local, single-user C++17 command-line password manager. It will store account names, usernames, and passwords in one encrypted vault file. It is an educational project, not a production password manager.

## Architecture

The application has four components:

1. **Command-line interface (CLI):** Shows the menu, reads input, hides passphrase entry, and displays an account only when requested.
2. **User-management module:** Manages vault entries in memory: add, list, find, and delete. “User-management” here means managing the single user's saved accounts; there are no multiple vault users.
3. **Encryption module:** Derives a key from the master passphrase, encrypts the vault before saving, and checks and decrypts it when opening.
4. **Storage layer:** Reads and writes the encrypted vault file. It does not need to know the master passphrase or understand account entries.

Planned data flow:

    Unlock:
    CLI asks for master passphrase
      → Storage reads encrypted vault
      → Encryption derives key and authenticates/decrypts vault
      → User-management loads entries
      → CLI shows menu

    Save after adding or deleting an entry:
    CLI requests change
      → User-management updates entries
      → Encryption encrypts entries with a fresh nonce
      → Storage writes the encrypted vault file

The storage layer must never write plaintext entries to the vault file.

## Threat model

| Asset | Threat | Intended mitigation / limitation |
| --- | --- | --- |
| Master passphrase | Someone sees it while it is typed or finds it in logs | Hide terminal input; never print, log, or store the passphrase. A keylogger remains outside this program's control. |
| Master passphrase | Attacker steals the file and guesses passphrases offline | Encourage a long passphrase; use a random salt and Argon2id to make each guess more costly. A weak passphrase is still vulnerable. |
| Vault at rest | Attacker reads the vault file | Encrypt the whole vault. Restrict file permissions to the owner. File permissions alone do not stop malware running as the owner. |
| Vault at rest | Attacker modifies or corrupts the file | Use authenticated encryption and reject a vault that fails authentication. This does not detect replacement with an older, valid copy. |
| Vault at rest | A save is interrupted | Write a temporary file and rename it over the vault after a successful write. Backups and older disk copies need separate protection. |
| Vault in memory | Another program or a compromised OS reads decrypted passwords | Keep the vault unlocked only while needed and clear sensitive buffers where practical. Ordinary C++ strings and a compromised OS remain risks. |
| Interface | Password appears on-screen or in terminal history | Hide input; show a saved password only after an explicit View action. The displayed password can still remain in scrollback or be screen-recorded. |

## Initial vault format

The proposed binary file layout is:

    "VLT1" | random salt | nonce | authentication tag + ciphertext

`VLT1` identifies this format version. The salt and nonce are not secrets. The ciphertext contains the entire list of entries, including account names, so the file does not reveal those names directly.

Before encryption, entries will use a count followed by length-prefixed site/name, username, and password fields. The reader will check file size, entry count, and field lengths before accepting data. Cryptographic settings are tied to the format version; a future settings change will require a new version or additional header fields.

## Initial cryptographic decisions

- Use libsodium's Argon2id password-based key derivation to turn the master passphrase and random salt into a symmetric key.
- Use libsodium `crypto_secretbox_easy` and `crypto_secretbox_open_easy` for encryption and authentication.
- Generate a new random nonce on every save with libsodium. Reusing a nonce with the same key must be avoided.
- Store the salt and nonce with the ciphertext, but never store the master passphrase or derived key in the file.

No custom encryption algorithm will be implemented.

## Current status

Checkpoint 1 is design only. The application, tests, and build instructions for the finished program will be added in later checkpoints.
