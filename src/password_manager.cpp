#include "terminal.hpp"
#include "crypto.hpp"
#include "entries.hpp"
#include "storage.hpp"

#include <cstdlib>
#include <iostream>
#include <sys/file.h>

// Clear these buffers when their objects leave scope.
// This does not guarantee removal of every possible memory copy.
struct SecretText {
    std::string value;

    ~SecretText() {
        if (!value.empty()) {
            sodium_memzero(value.data(), value.size());
        }
    }
};

struct SecretBytes {
    vaultcrypto::Bytes value;

    ~SecretBytes() {
        if (!value.empty()) {
            sodium_memzero(value.data(), value.size());
        }
    }
};

std::string vault_directory() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        throw std::runtime_error("HOME is not set.");
    }

    const std::string directory =
        std::string(home) + "/.cpp_password_manager";

    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
        throw std::runtime_error("Cannot create vault directory.");
    }

    struct stat info{};
    if (lstat(directory.c_str(), &info) != 0 ||
        !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid() ||
        (info.st_mode & 077) != 0) {
        throw std::runtime_error(
            "Vault directory must be owned by you and private.");
    }

    return directory;
}

bool vault_exists(const std::string& path) {
    struct stat info{};
    if (lstat(path.c_str(), &info) == 0) {
        return true;
    }
    if (errno == ENOENT) {
        return false;
    }
    throw std::runtime_error("Cannot inspect vault path.");
}

void check_master_length(const std::string& password, bool creating) {
    if (password.empty() || password.size() > 1024 ||
        (creating && password.size() < 12)) {
        throw std::runtime_error(
            "New master passphrases require 12-1024 bytes; "
            "unlock input must be nonempty and at most 1024 bytes.");
    }
}

int main() {
    try {
        if (sodium_init() < 0) {
            throw std::runtime_error("Encryption library initialisation failed.");
        }

        const std::string directory = vault_directory();
        const std::string path = directory + "/vault.vault";

        // Keep a separate lock file because saving replaces the vault file.
        vaultstorage::FileDescriptor lock_file(open(
            (directory + "/session.lock").c_str(),
            O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            0600));

        struct stat lock_info{};
        if (lock_file.get() < 0 ||
            fstat(lock_file.get(), &lock_info) != 0 ||
            !S_ISREG(lock_info.st_mode) ||
            lock_info.st_uid != geteuid() ||
            (lock_info.st_mode & 077) != 0) {
            throw std::runtime_error("Cannot open private session lock.");
        }

        if (flock(lock_file.get(), LOCK_EX | LOCK_NB) != 0) {
            throw std::runtime_error(
                "Cannot lock vault; another instance may be running.");
        }

        const bool creating = !vault_exists(path);
        vaultstorage::FileData file;

        if (creating) {
            std::cout << "Creating a new vault. Use dummy credentials only.\n";
            file.salt = vaultcrypto::random_salt();
        } else {
            file = vaultstorage::load(path);
        }

        SecretText master{
            read_password(creating
                ? "Choose a master passphrase (12+ characters): "
                : "Master passphrase: ")
        };

        check_master_length(master.value, creating);

        if (creating) {
            SecretText confirmation{
                read_password("Confirm master passphrase: ")
            };

            if (master.value != confirmation.value) {
                throw std::runtime_error("Passphrases do not match.");
            }
        }

        const vaultcrypto::Key key(master.value, file.salt);
        sodium_memzero(master.value.data(), master.value.size());
        master.value.clear();

        std::vector<vaultentries::Entry> entries;

        if (creating) {
            SecretBytes plaintext{vaultentries::encode(entries)};
            file.ciphertext = vaultcrypto::encrypt(
                plaintext.value, key, file.nonce);

            vaultstorage::save(path, file);
            std::cout << "Vault created successfully.\n";
        } else {
            SecretBytes plaintext{
                vaultcrypto::decrypt(file.ciphertext, key, file.nonce)
            };

            entries = vaultentries::decode(plaintext.value);
            std::cout << "Vault unlocked successfully.\n";
        }

        std::cout << "Stored accounts: " << entries.size() << '\n';
        std::cout << "Account menu will be added next.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
