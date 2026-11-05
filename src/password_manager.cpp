#include <sodium.h>
#include <iostream>
#include <stdexcept>
#include "terminal.hpp"

int main() {
    try {
        if (sodium_init() < 0) {
            throw std::runtime_error("Encryption library initialisation failed.");
        }

        std::cout << "Password Manager - hidden input test\n";
        std::cout << "Use a dummy password, not a real one.\n";

        std::string password = read_password("Test password: ");

        if (!password.empty()) {
            sodium_memzero(password.data(), password.size());
        }
        password.clear();

        std::cout << "Input received and cleared without displaying it.\n";
        std::cout << "Authentication and vault storage are not implemented yet.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
