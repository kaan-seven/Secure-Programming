#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>

class HiddenInput {
    termios original_{};

public:
    HiddenInput() {
        if (!isatty(STDIN_FILENO) ||
            tcgetattr(STDIN_FILENO, &original_) != 0) {
            throw std::runtime_error("An interactive terminal is required.");
        }

        termios hidden = original_;
        hidden.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            throw std::runtime_error("Cannot hide terminal input.");
        }
    }

    HiddenInput(const HiddenInput&) = delete;
    HiddenInput& operator=(const HiddenInput&) = delete;

    ~HiddenInput() {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_);
    }
};

inline std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string password;

    {
        HiddenInput hidden;

        if (!std::getline(std::cin, password)) {
            throw std::runtime_error("Password input ended unexpectedly.");
        }
    }

    std::cout << '\n';
    return password;
}
