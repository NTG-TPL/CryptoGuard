#include "stream_utils.h"

#include <istream>
#include <ostream>
#include <stdexcept>

namespace CryptoGuard::detail {

void CheckInputStream(const std::istream &in) {
    if (!in.good()) {
        throw std::runtime_error{"input stream is not ready for reading"};
    }
}

void CheckOutputStream(const std::ostream &out) {
    if (!out.good()) {
        throw std::runtime_error{"output stream is not ready for writing"};
    }
}

void CheckStreams(const std::iostream &inStream, const std::iostream &outStream) {
    if (&inStream == &outStream) {
        throw std::invalid_argument{"input and output streams must be different"};
    }
    CheckInputStream(inStream);
    CheckOutputStream(outStream);
}

std::size_t ReadChunk(std::istream &in, std::span<char> buffer) {
    in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    if (in.bad() || (in.fail() && !in.eof())) {
        throw std::runtime_error{"failed to read from the input stream"};
    }
    return static_cast<std::size_t>(in.gcount());
}

void WriteChunk(std::ostream &out, std::span<const unsigned char> data) {
    out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) {
        throw std::runtime_error{"failed to write to the output stream"};
    }
}

}  // namespace CryptoGuard::detail
