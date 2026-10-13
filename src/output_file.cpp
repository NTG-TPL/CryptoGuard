#include "output_file.h"

#include <format>
#include <ios>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace CryptoGuard {

// TODO :: Think about using a tmp file (to avoid data loss in the event of errors)
OutputFile::OutputFile(std::filesystem::path path)
    : path_(std::move(path)), stream_(path_, std::ios::out | std::ios::binary | std::ios::noreplace) {
    if (!stream_.is_open()) {
        std::error_code error;
        if (std::filesystem::exists(path_, error)) {
            throw std::runtime_error{std::format("output file '{}' already exists", path_.string())};
        }
        throw std::runtime_error{std::format("failed to open output file '{}'", path_.string())};
    }
}

OutputFile::~OutputFile() {
    if (!committed_) {
        stream_.close();
        std::error_code error;
        std::filesystem::remove(path_, error);
    }
}

void OutputFile::Commit() {
    stream_.close();
    if (stream_.fail()) {
        throw std::runtime_error{std::format("failed to write output file '{}'", path_.string())};
    }
    committed_ = true;
}

}  // namespace CryptoGuard
