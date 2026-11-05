#include "../src/crypto.hpp"
#include <iostream>
#include <stdexcept>

using namespace vaultcrypto;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

bool rejects(const Bytes& ciphertext, const Key& key,
             const Nonce& nonce) {
    try {
        Bytes result = decrypt(ciphertext, key, nonce);
        if (!result.empty()) {
            sodium_memzero(result.data(), result.size());
        }
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

int main() {
    try {
        require(sodium_init() >= 0, "Library initialisation failed.");

        // Dummy test data only; never use real passwords in tests.
        const Salt salt = random_salt();
        const Key correct_key("dummy-master-passphrase", salt);
        const Key wrong_key("different-dummy-passphrase", salt);

        const Bytes original{'t', 'e', 's', 't'};
        Nonce nonce{};
        const Bytes ciphertext = encrypt(original, correct_key, nonce);

        Bytes recovered = decrypt(ciphertext, correct_key, nonce);
        require(recovered == original, "Round-trip test failed.");
        sodium_memzero(recovered.data(), recovered.size());
        std::cout << "PASS: encryption/decryption round trip\n";

        require(rejects(ciphertext, wrong_key, nonce),
                "Wrong password was accepted.");
        std::cout << "PASS: wrong password rejected\n";

        Bytes modified = ciphertext;
        modified.back() ^= 1;
        require(rejects(modified, correct_key, nonce),
                "Modified ciphertext was accepted.");
        std::cout << "PASS: modified ciphertext rejected\n";

        Nonce changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        require(rejects(ciphertext, correct_key, changed_nonce),
                "Modified nonce was accepted.");
        std::cout << "PASS: modified nonce rejected\n";

        const Bytes truncated(crypto_secretbox_MACBYTES - 1, 0);
        require(rejects(truncated, correct_key, nonce),
                "Truncated ciphertext was accepted.");
        std::cout << "PASS: truncated ciphertext rejected\n";

        std::cout << "All crypto tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
