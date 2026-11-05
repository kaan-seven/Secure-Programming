#include "../src/entries.hpp"
#include <iostream>
#include <stdexcept>

using namespace vaultentries;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

bool rejects(const Bytes& bytes) {
    try {
        decode(bytes);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

int main() {
    try {
        // Dummy credentials only.
        const std::vector<Entry> original{
            {"Example site", "test-user", "dummy-password"},
            {"Another site", "", "another-dummy-password"}
        };

        const Bytes encoded = encode(original);
        const auto recovered = decode(encoded);

        require(recovered.size() == original.size(),
                "Entry count differs.");

        for (std::size_t i = 0; i < original.size(); ++i) {
            require(recovered[i].name == original[i].name &&
                    recovered[i].username == original[i].username &&
                    recovered[i].password == original[i].password,
                    "Recovered entry differs.");
        }
        std::cout << "PASS: credential records round trip\n";

        require(decode(encode({})).empty(), "Empty vault failed.");
        std::cout << "PASS: empty vault supported\n";

        Bytes truncated = encoded;
        truncated.pop_back();
        require(rejects(truncated), "Truncated record accepted.");
        std::cout << "PASS: truncated record rejected\n";

        Bytes trailing = encoded;
        trailing.push_back(0);
        require(rejects(trailing), "Trailing data accepted.");
        std::cout << "PASS: trailing data rejected\n";

        Bytes excessive_count;
        write_u32(excessive_count,
                  static_cast<std::uint32_t>(MAX_ENTRIES + 1));
        require(rejects(excessive_count), "Excessive count accepted.");
        std::cout << "PASS: excessive entry count rejected\n";

        Bytes excessive_field;
        write_u32(excessive_field, 1);
        write_u32(excessive_field,
                  static_cast<std::uint32_t>(MAX_FIELD + 1));
        require(rejects(excessive_field), "Oversized field accepted.");
        std::cout << "PASS: oversized field rejected\n";

        std::cout << "All entry tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
