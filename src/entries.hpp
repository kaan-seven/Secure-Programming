#pragma once

#include "crypto.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace vaultentries {

using vaultcrypto::Bytes;

constexpr std::size_t MAX_ENTRIES = 100;
constexpr std::size_t MAX_FIELD = 4096;

struct Entry {
    std::string name;
    std::string username;
    std::string password;
};

inline void write_u32(Bytes& output, std::uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i) {
        output.push_back(
            static_cast<unsigned char>(value >> (8 * i)));
    }
}

inline std::uint32_t read_u32(const Bytes& input,
                              std::size_t& position) {
    if (position > input.size() ||
        input.size() - position < 4) {
        throw std::runtime_error("Truncated vault record.");
    }

    std::uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(input[position++])
                 << (8 * i);
    }
    return value;
}

inline void write_field(Bytes& output, const std::string& field) {
    if (field.size() > MAX_FIELD) {
        throw std::runtime_error("Field exceeds 4096 bytes.");
    }

    write_u32(output, static_cast<std::uint32_t>(field.size()));
    output.insert(output.end(), field.begin(), field.end());
}

inline std::string read_field(const Bytes& input,
                               std::size_t& position) {
    const std::uint32_t length = read_u32(input, position);

    if (length > MAX_FIELD || length > input.size() - position) {
        throw std::runtime_error("Invalid vault field length.");
    }

    std::string field(
        reinterpret_cast<const char*>(input.data() + position),
        length);

    position += length;
    return field;
}

inline Bytes encode(const std::vector<Entry>& entries) {
    if (entries.size() > MAX_ENTRIES) {
        throw std::runtime_error("Vault exceeds 100 entries.");
    }

    Bytes output;
    write_u32(output, static_cast<std::uint32_t>(entries.size()));

    for (const auto& entry : entries) {
        if (entry.name.empty() || entry.password.empty()) {
            throw std::runtime_error(
                "Account name and password must not be empty.");
        }

        write_field(output, entry.name);
        write_field(output, entry.username);
        write_field(output, entry.password);
    }

    if (output.size() > vaultcrypto::MAX_PLAINTEXT) {
        throw std::runtime_error("Vault data is too large.");
    }

    return output;
}

inline std::vector<Entry> decode(const Bytes& input) {
    if (input.size() > vaultcrypto::MAX_PLAINTEXT) {
        throw std::runtime_error("Vault data is too large.");
    }

    std::size_t position = 0;
    const std::uint32_t count = read_u32(input, position);

    if (count > MAX_ENTRIES) {
        throw std::runtime_error("Invalid vault entry count.");
    }

    std::vector<Entry> entries;
    entries.reserve(count);

    for (std::uint32_t i = 0; i < count; ++i) {
        Entry entry;
        entry.name = read_field(input, position);
        entry.username = read_field(input, position);
        entry.password = read_field(input, position);

        if (entry.name.empty() || entry.password.empty()) {
            throw std::runtime_error("Invalid empty vault field.");
        }

        entries.push_back(std::move(entry));
    }

    if (position != input.size()) {
        throw std::runtime_error("Unexpected trailing vault data.");
    }

    return entries;
}

} // namespace vaultentries
