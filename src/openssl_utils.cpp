#include "openssl_utils.h"

#include <array>
#include <format>
#include <openssl/err.h>
#include <stdexcept>
#include <string>

namespace CryptoGuard::detail {

namespace {

std::string DrainOpenSslErrors() {
    std::string details;
    while (const auto code = ERR_get_error()) {
        std::array<char, 256> buffer{};
        ERR_error_string_n(code, buffer.data(), buffer.size());
        if (!details.empty()) {
            details += "; ";
        }
        details += buffer.data();
    }
    return details;
}

}  // namespace

void ThrowOpenSslError(std::string_view what) {
    const auto details = DrainOpenSslErrors();
    if (details.empty()) {
        throw std::runtime_error{std::string{what}};
    }
    throw std::runtime_error{std::format("{} (OpenSSL: {})", what, details)};
}

void CheckOpenSslResult(int result, std::string_view what) {
    if (result != 1) {
        ThrowOpenSslError(what);
    }
}

}  // namespace CryptoGuard::detail
