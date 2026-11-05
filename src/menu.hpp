#pragma once

#include "terminal.hpp"
#include "entries.hpp"
#include "storage.hpp"
#include <utility>

namespace vaultmenu {

inline void wipe(std::string& text) {
    if (!text.empty()) {
        sodium_memzero(text.data(), text.size());
    }
    text.clear();
}

// Clear active entry buffers on normal exit or C++ exception.
struct EntryCleanup {
    std::vector<vaultentries::Entry>& entries;

    ~EntryCleanup() {
        for (auto& entry : entries) {
            wipe(entry.name);
            wipe(entry.username);
            wipe(entry.password);
        }
    }
};

struct PlaintextBuffer {
    vaultcrypto::Bytes bytes;

    ~PlaintextBuffer() {
        if (!bytes.empty()) {
            sodium_memzero(bytes.data(), bytes.size());
        }
    }
};

inline std::string prompt(const std::string& label) {
    std::cout << label << std::flush;
    std::string text;

    if (!std::getline(std::cin, text)) {
        throw std::runtime_error("Input ended.");
    }

    if (text.size() > vaultentries::MAX_FIELD) {
        throw std::runtime_error("Input exceeds 4096 bytes.");
    }

    return text;
}

// Do not allow stored terminal control characters to affect output.
inline std::string display_text(const std::string& text) {
    std::string result;
    for (unsigned char character : text) {
        result += (character >= 32 && character <= 126)
            ? static_cast<char>(character) : '?';
    }
    return result;
}

inline void persist(
    const std::string& path,
    const vaultcrypto::Key& key,
    vaultstorage::FileData& file,
    const std::vector<vaultentries::Entry>& entries) {

    PlaintextBuffer plaintext{vaultentries::encode(entries)};

    file.ciphertext = vaultcrypto::encrypt(
        plaintext.bytes, key, file.nonce);

    vaultstorage::save(path, file);
}

inline void run(
    std::vector<vaultentries::Entry>& entries,
    const vaultcrypto::Key& key,
    vaultstorage::FileData& file,
    const std::string& path) {

    EntryCleanup cleanup{entries};

    while (true) {
        std::cout << "\n1) Add account\n"
                  << "2) List accounts\n"
                  << "3) View masked account details\n"
                  << "4) Delete account\n"
                  << "5) Quit and lock\n";

        const std::string choice = prompt("> ");

        if (choice == "5") {
            std::cout << "Vault closed.\n";
            return;
        }

        if (choice == "1") {
            if (entries.size() >= vaultentries::MAX_ENTRIES) {
                std::cout << "Vault is full.\n";
                continue;
            }

            std::string name = prompt("Account name: ");
            if (name.empty()) {
                std::cout << "Account name cannot be empty.\n";
                continue;
            }

            bool duplicate = false;
            for (const auto& entry : entries) {
                if (entry.name == name) {
                    duplicate = true;
                }
            }

            if (duplicate) {
                std::cout << "That account name already exists.\n";
                continue;
            }

            // Place the entry under cleanup protection before reading secrets.
            entries.emplace_back();
            auto& entry = entries.back();
            entry.name = std::move(name);
            entry.username = prompt("Username: ");
            entry.password = read_password("Account password: ");

            if (entry.password.empty() ||
                entry.password.size() > vaultentries::MAX_FIELD) {
                wipe(entry.name);
                wipe(entry.username);
                wipe(entry.password);
                entries.pop_back();
                std::cout << "Password must contain 1-4096 bytes.\n";
                continue;
            }

            persist(path, key, file, entries);
            std::cout << "Account saved in encrypted vault.\n";
        } else if (choice == "2") {
            if (entries.empty()) {
                std::cout << "No accounts saved.\n";
            }

            for (const auto& entry : entries) {
                std::cout << "- " << display_text(entry.name) << '\n';
            }
        } else if (choice == "3" || choice == "4") {
            const std::string name = prompt("Account name: ");
            std::size_t index = 0;

            while (index < entries.size() &&
                   entries[index].name != name) {
                ++index;
            }

            if (index == entries.size()) {
                std::cout << "Account not found.\n";
                continue;
            }

            if (choice == "3") {
                const auto& entry = entries[index];
                std::cout << "Account: " << display_text(entry.name)
                          << "\nUsername: " << display_text(entry.username)
                          << "\nPassword: [hidden]\n";
            } else {
                if (prompt("Type DELETE to confirm: ") != "DELETE") {
                    std::cout << "Deletion cancelled.\n";
                    continue;
                }

                wipe(entries[index].name);
                wipe(entries[index].username);
                wipe(entries[index].password);

                entries.erase(entries.begin() + index);
                persist(path, key, file, entries);
                std::cout << "Account deleted.\n";
            }
        } else {
            std::cout << "Choose a number from 1 to 5.\n";
        }
    }
}

} // namespace vaultmenu
