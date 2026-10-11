#include "crypto_guard_ctx.h"

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <stdexcept>
#include <utility>

namespace CryptoGuard {

namespace {

struct AesCipherParams {
    static constexpr std::size_t kKeySize = 32;
    static constexpr std::size_t kIvSize = 16;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    int encrypt{};
    std::array<unsigned char, kKeySize> key{};
    std::array<unsigned char, kIvSize> iv{};
};

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() {
        if (OpenSSL_add_all_algorithms() != 1) {
            throw std::runtime_error{"Failed to initialize OpenSSL"};
        }
    }
    ~Impl() { EVP_cleanup(); }

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;
    Impl(Impl &&) = delete;
    Impl &operator=(Impl &&) = delete;

    void EncryptFile(std::iostream &, std::iostream &, std::string_view) {}
    void DecryptFile(std::iostream &, std::iostream &, std::string_view) {}
    std::string CalculateChecksum(std::iostream &) { return "NOT_IMPLEMENTED"; }

private:
    static AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        if (!std::in_range<int>(password.size())) {
            throw std::invalid_argument{"Password is too long"};
        }

        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        const int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                          reinterpret_cast<const unsigned char *>(password.data()),
                                          static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());
        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }
        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
