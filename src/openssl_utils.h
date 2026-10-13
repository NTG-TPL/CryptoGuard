#pragma once

#include <memory>
#include <openssl/evp.h>
#include <string_view>

namespace CryptoGuard::detail {

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

[[noreturn]] void ThrowOpenSslError(std::string_view what);

void CheckOpenSslResult(int result, std::string_view what);

template <typename T>
T *CheckOpenSslResult(T *ptr, std::string_view what) {
    if (ptr == nullptr) {
        ThrowOpenSslError(what);
    }
    return ptr;
}

}  // namespace CryptoGuard::detail
