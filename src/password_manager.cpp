#include <sodium.h>
#include <iostream>

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialise the encryption library.\n";
        return 1;
    }

    std::cout << "Password Manager\n";
    std::cout << "Encryption library initialised successfully.\n";
    std::cout << "Vault features are not implemented yet.\n";

    return 0;
}
