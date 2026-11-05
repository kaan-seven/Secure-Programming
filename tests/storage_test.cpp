#include "../src/storage.hpp"
#include <iostream>
#include <stdexcept>

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct TestDirectory {
    std::string directory;
    std::string file;

    TestDirectory() {
        char pattern[] = "/tmp/password-manager-test-XXXXXX";
        char* created = mkdtemp(pattern);

        if (!created) {
            throw std::runtime_error("Cannot create test directory.");
        }

        directory = created;
        file = directory + "/test.vault";
    }

    ~TestDirectory() {
        unlink(file.c_str());
        rmdir(directory.c_str());
    }
};

int main() {
    try {
        require(sodium_init() >= 0, "Library initialisation failed.");
        TestDirectory temporary;

        vaultstorage::FileData original;
        original.salt = vaultcrypto::random_salt();

        const vaultcrypto::Key key(
            "dummy-master-passphrase", original.salt);

        const vaultcrypto::Bytes plaintext{'t', 'e', 's', 't'};

        original.ciphertext = vaultcrypto::encrypt(
            plaintext, key, original.nonce);

        vaultstorage::save(temporary.file, original);

        const auto loaded = vaultstorage::load(temporary.file);

        require(loaded.salt == original.salt, "Salt changed.");
        require(loaded.nonce == original.nonce, "Nonce changed.");
        require(loaded.ciphertext == original.ciphertext,
                "Ciphertext changed.");
        std::cout << "PASS: encrypted file saved and loaded\n";

        // Derive a fresh key using the salt read from disk.
        const vaultcrypto::Key reopened_key(
            "dummy-master-passphrase", loaded.salt);

        auto recovered = vaultcrypto::decrypt(
            loaded.ciphertext, reopened_key, loaded.nonce);

        require(recovered == plaintext, "Recovered data differs.");
        sodium_memzero(recovered.data(), recovered.size());
        std::cout << "PASS: saved data decrypted with a fresh key\n";

        struct stat info{};
        require(stat(temporary.file.c_str(), &info) == 0,
                "Cannot inspect permissions.");
        require((info.st_mode & 0777) == 0600,
                "Expected owner-only read/write permissions.");
        std::cout << "PASS: vault permissions are 0600\n";

        require(chmod(temporary.file.c_str(), 0644) == 0,
                "Cannot change test permissions.");

        bool rejected = false;
        try {
            vaultstorage::load(temporary.file);
        } catch (const std::runtime_error&) {
            rejected = true;
        }

        require(rejected, "Unsafe permissions were accepted.");
        std::cout << "PASS: unsafe file permissions rejected\n";

        std::cout << "All storage tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
