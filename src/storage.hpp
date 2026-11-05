#pragma once

#include "crypto.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vaultstorage {

using vaultcrypto::Bytes;
using vaultcrypto::Salt;
using vaultcrypto::Nonce;

constexpr std::size_t HEADER_SIZE =
    4 + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;

constexpr std::size_t MAX_FILE_SIZE =
    HEADER_SIZE + crypto_secretbox_MACBYTES +
    vaultcrypto::MAX_PLAINTEXT;

struct FileData {
    Salt salt{};
    Nonce nonce{};
    Bytes ciphertext;
};

// Closes the file even if a C++ exception occurs.
class FileDescriptor {
    int fd_;

public:
    explicit FileDescriptor(int fd) : fd_(fd) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    ~FileDescriptor() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    int get() const { return fd_; }

    void close_checked() {
        int old = fd_;
        fd_ = -1;
        if (close(old) != 0) {
            throw std::runtime_error("Cannot close vault file.");
        }
    }
};

inline FileData load(const std::string& path) {
    FileDescriptor fd(open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));

    if (fd.get() < 0) {
        throw std::runtime_error("Cannot open vault file.");
    }

    struct stat info{};
    if (fstat(fd.get(), &info) != 0 ||
        !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() ||
        (info.st_mode & 077) != 0) {
        throw std::runtime_error(
            "Vault must be a regular file owned by you with private permissions.");
    }

    if (info.st_size <
            static_cast<off_t>(HEADER_SIZE + crypto_secretbox_MACBYTES) ||
        info.st_size > static_cast<off_t>(MAX_FILE_SIZE)) {
        throw std::runtime_error("Invalid vault file size.");
    }

    Bytes bytes(static_cast<std::size_t>(info.st_size));
    std::size_t position = 0;

    while (position < bytes.size()) {
        ssize_t count = read(
            fd.get(), bytes.data() + position, bytes.size() - position);

        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("Cannot read complete vault file.");
        }
        position += static_cast<std::size_t>(count);
    }

    const unsigned char magic[] = {'V', 'L', 'T', '1'};
    if (!std::equal(magic, magic + 4, bytes.begin())) {
        throw std::runtime_error("Unknown vault format.");
    }

    FileData result;
    std::copy_n(bytes.data() + 4,
                result.salt.size(), result.salt.begin());

    std::copy_n(bytes.data() + 4 + result.salt.size(),
                result.nonce.size(), result.nonce.begin());

    result.ciphertext.assign(
        bytes.begin() + HEADER_SIZE, bytes.end());

    return result;
}

inline void save(const std::string& path, const FileData& data) {
    if (data.ciphertext.size() < crypto_secretbox_MACBYTES ||
        data.ciphertext.size() >
            vaultcrypto::MAX_PLAINTEXT + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Invalid ciphertext size.");
    }

    Bytes bytes{'V', 'L', 'T', '1'};
    bytes.insert(bytes.end(), data.salt.begin(), data.salt.end());
    bytes.insert(bytes.end(), data.nonce.begin(), data.nonce.end());
    bytes.insert(bytes.end(),
                 data.ciphertext.begin(), data.ciphertext.end());

    std::string temporary = path + ".tmpXXXXXX";
    FileDescriptor fd(mkstemp(temporary.data()));

    if (fd.get() < 0) {
        throw std::runtime_error("Cannot create temporary vault.");
    }

    try {
        if (fchmod(fd.get(), 0600) != 0) {
            throw std::runtime_error("Cannot set vault permissions.");
        }

        std::size_t position = 0;

        while (position < bytes.size()) {
            ssize_t count = write(
                fd.get(), bytes.data() + position, bytes.size() - position);

            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error("Cannot write vault.");
            }
            position += static_cast<std::size_t>(count);
        }

        if (fsync(fd.get()) != 0) {
            throw std::runtime_error("Cannot sync vault file.");
        }

        fd.close_checked();

        if (rename(temporary.c_str(), path.c_str()) != 0) {
            throw std::runtime_error("Cannot replace vault file.");
        }
    } catch (...) {
        unlink(temporary.c_str());
        throw;
    }
}

} // namespace vaultstorage
