# Secure Programming — Password Manager

## Scope

This repository is for a Secure Programming course project: a local, single-user password manager planned in C++17 with libsodium. Checkpoint 1 contains the design, not a working application. Do not use it to store real passwords.

## Planned terminal menu

1. Add an account
2. List account names
3. View an account
4. Delete an account
5. Quit

The application will prompt for a master passphrase when creating or unlocking the vault. Adding an account will allow the user to enter or generate a password.

## Build and run

Implementation is planned for a later checkpoint, so there is nothing to build or run yet. The planned build environment is Ubuntu/Debian or WSL with g++ and libsodium-dev.

Planned commands once src/password_manager.cpp exists:

    g++ -std=c++17 -Wall -Wextra src/password_manager.cpp -lsodium -o password_manager
    ./password_manager

## Project files

- README.md — project scope and planned usage.
- design.md — architecture, threat model, and vault design (to be added).
