# Secure Programming — Password Manager

## Scope and status

A local, single-user password manager written in C++17 with libsodium.

Checkpoint 2 implements:
- Creation and reopening of an encrypted vault.
- Master-passphrase authentication.
- Adding and listing account records.
- Viewing account names and usernames with passwords always masked.
- Deleting accounts with confirmation.
- Automated tests for cryptography, file storage, and record parsing.

This is an educational prototype. Use dummy credentials only.
Password retrieval/export, password generation, and a graphical interface
are not implemented.

## Supported environment

Ubuntu Linux, including Ubuntu running under WSL on Windows.

The implementation uses Linux/POSIX terminal and filesystem APIs.
It is not currently a native Windows application.

## Install dependencies

On a fresh Ubuntu installation:

```bash
sudo apt update
sudo apt install build-essential git libsodium-dev
```

## Get the source

```bash
git clone [https://github.com/kaan-seven/Secure-Programming.git](https://github.com/kaan-seven/Secure-Programming.git)
cd Secure-Programming
```

If you already cloned the repository, use that existing folder instead.

## Build

From the repository root:

```bash
g++ -std=c++17 -Wall -Wextra -Wpedantic \
    src/password_manager.cpp -lsodium -o password_manager
```

## Run

```bash
./password_manager
```

Run in an interactive terminal.

On first use, choose and confirm a master passphrase of 12–1024 bytes.
For later runs, enter the same passphrase to unlock the vault.

Master passphrases and account passwords are entered without echo.
There is no master-passphrase recovery feature.

Menu:

1. Add account
2. List accounts
3. View masked account details
4. Delete account
5. Quit and lock

Account names must be unique when added through the interface.
Account names and passwords must not be empty.
Fields are limited to 4096 bytes; the vault supports up to 100 accounts.
The interface displays non-ASCII/control bytes in names and usernames as
question marks. Password fields are never printed, including their length.

## Vault location

The application uses:

```text
~/.cpp_password_manager/vault.vault
```

The directory is private to the current user, and the vault is saved with
owner-only read/write permissions (0600).

A separate session.lock file provides an advisory lock so cooperating
instances do not edit the same vault simultaneously.

Vault data is stored outside this repository. Do not commit real vaults,
passwords, or credentials.

## Cryptographic design

- Argon2id derives a 256-bit key from the master passphrase and random salt.
- The VLT1 format fixes Argon2id to opslimit 2 and 64 MiB of memory.
- Libsodium secretbox provides XSalsa20-Poly1305 authenticated encryption.
- Every save generates a fresh random nonce.
- Incorrect keys and failed authentication cause decryption to be rejected.
- The entire record collection is encrypted, including account names.

File layout:

```text
VLT1 | salt | nonce | authentication tag + ciphertext
```

The salt and nonce are public. The master passphrase and derived key are
not stored in the vault file.

The encrypted plaintext consists of a 32-bit little-endian entry count,
followed by three length-prefixed fields per entry: name, username,
and password. Each field length is a 32-bit little-endian byte count.

## Run automated tests

From the repository root:

```bash
mkdir -p build

g++ -std=c++17 -Wall -Wextra -Wpedantic \
    tests/crypto_test.cpp -lsodium -o build/crypto_test

g++ -std=c++17 -Wall -Wextra -Wpedantic \
    tests/storage_test.cpp -lsodium -o build/storage_test

g++ -std=c++17 -Wall -Wextra -Wpedantic \
    tests/entries_test.cpp -lsodium -o build/entries_test

./build/crypto_test
./build/storage_test
./build/entries_test
```

Each program returns a nonzero exit status on test failure.

## Known limitations

- Not audited or suitable for storing real secrets.
- No inactivity timeout; quit to close the unlocked vault.
- Decrypted entries remain in memory while unlocked.
- Buffer clearing is best effort; C++ strings and temporary copies may
  leave remnants. Memory is not locked against swapping.
- A compromised OS, keylogger, or privileged attacker can capture secrets.
- Authenticated encryption does not detect replacement with an older
  valid vault or prevent deletion of the vault.
- Atomic replacement and syncing the file reduce save-interruption risks,
  but full power-loss durability is not guaranteed.
- Input length is checked after reading a line, not while reading it.
- Abrupt termination may leave terminal echo disabled; run `stty echo`
  in that terminal to restore it.
- Password retrieval/export, secure backups, and passphrase changes are
  not implemented.

## Repository contents

- src/password_manager.cpp — application startup and vault authentication.
- src/terminal.hpp — hidden terminal input.
- src/crypto.hpp — key derivation and authenticated encryption.
- src/storage.hpp — encrypted file storage.
- src/entries.hpp — account-record encoding and decoding.
- src/menu.hpp — account-management interface.
- tests/ — automated component tests.
- design.md — architecture and threat model.
- README.md — build, run, and test instructions.
