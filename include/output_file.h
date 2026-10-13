#pragma once

#include <filesystem>
#include <fstream>

namespace CryptoGuard {

class OutputFile {
public:
    explicit OutputFile(std::filesystem::path path);
    ~OutputFile();

    OutputFile(const OutputFile &) = delete;
    OutputFile &operator=(const OutputFile &) = delete;
    OutputFile(OutputFile &&) = delete;
    OutputFile &operator=(OutputFile &&) = delete;

    std::fstream &Stream() noexcept { return stream_; }

    void Commit();

private:
    std::filesystem::path path_;
    std::fstream stream_;
    bool committed_ = false;
};

}  // namespace CryptoGuard
