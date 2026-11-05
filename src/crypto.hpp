#pragma once

#include <sodium.h>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>

namespace vaultcrypto {

using Bytes = std::vector<unsigned char>;
using Salt = std::array<unsigned char, crypto_pwhash_SALTBYTES>;
using Nonce = std::array<unsigned char, crypto_secretbox_NONCEBYTES>;

constexpr std::size_t MAX_PLAINTEXT = 1024 * 1024;

// Fixed parameters for our first vault format:
// Argon2id, two operations, 64 MiB of memory.
constexpr unsigned long long KDF_OPS = 2;
constexpr std::size_t KDF_MEMORY = 64 * 1024 * 1024;

class Key {
    std::array<unsigned char, crypto_secretbox_KEYBYTES> bytes_{};

public:
    Key(const std::string& password, const Salt& salt) {
        if (crypto_pwhash(
                bytes_.data(), bytes_.size(),
                password.data(), password.size(),
                salt.data(), KDF_OPS, KDF_MEMORY,
                crypto_pwhash_ALG_ARGON2ID13) != 0) {
            sodium_memzero(bytes_.data(), bytes_.size());
            throw std::runtime_error("Key derivation failed.");
        }
    }

    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;

    ~Key() {
        sodium_memzero(bytes_.data(), bytes_.size());
    }

    const unsigned char* data() const {
        return bytes_.data();
    }
};

inline Salt random_salt() {
    Salt salt{};
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

inline Bytes encrypt(const Bytes& plaintext, const Key& key,
                     Nonce& nonce) {
    if (plaintext.size() > MAX_PLAINTEXT) {
        throw std::runtime_error("Vault data is too large.");
    }

    randombytes_buf(nonce.data(), nonce.size());

    Bytes ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(
            ciphertext.data(), plaintext.data(), plaintext.size(),
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error("Encryption failed.");
    }

    return ciphertext;
}

inline Bytes decrypt(const Bytes& ciphertext, const Key& key,
                     const Nonce& nonce) {
    if (ciphertext.size() < crypto_secretbox_MACBYTES ||
        ciphertext.size() > MAX_PLAINTEXT + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Invalid ciphertext size.");
    }

    Bytes plaintext(ciphertext.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(
            plaintext.data(), ciphertext.data(), ciphertext.size(),
            nonce.data(), key.data()) != 0) {
        if (!plaintext.empty()) {
            sodium_memzero(plaintext.data(), plaintext.size());
        }
        throw std::runtime_error(
            "Wrong master password or damaged/modified vault.");
    }

    return plaintext;
}

} // namespace vaultcrypto
