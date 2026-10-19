#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <iosfwd>
#include <span>

namespace CryptoGuard::detail {

inline constexpr std::size_t CHUNK_SIZE = 4096;

void CheckInputStream(const std::istream &in);
void CheckOutputStream(const std::ostream &out);
void CheckStreams(const std::iostream &inStream, const std::iostream &outStream);

std::size_t ReadChunk(std::istream &in, std::span<char> buffer);
void WriteChunk(std::ostream &out, std::span<const unsigned char> data);

template <std::invocable<std::span<const char>> Consumer>
void ForEachChunk(std::istream &in, Consumer consume) {
    std::array<char, CHUNK_SIZE> buffer{};
    while (const auto bytesRead = ReadChunk(in, buffer)) {
        consume(std::span<const char>{buffer.data(), bytesRead});
    }
}

}  // namespace CryptoGuard::detail
