#include "crypto_guard_ctx.h"

#include "openssl_utils.h"
#include "stream_utils.h"

#include <array>
#include <cstddef>
#include <iomanip>
#include <istream>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <ostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace CryptoGuard {

using namespace detail;

namespace {

enum class CIPHER_MODE : int {
    DECRYPT = 0,
    ENCRYPT = 1,
};

struct AesCipherParams {
    static constexpr std::size_t KEY_SIZE = 32;  // AES-256 key size
    static constexpr std::size_t IV_SIZE = 16;   // AES block size (IV length)

    AesCipherParams() = default;
    ~AesCipherParams() {
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(iv.data(), iv.size());
    }

    AesCipherParams(const AesCipherParams &) = delete;
    AesCipherParams &operator=(const AesCipherParams &) = delete;
    AesCipherParams(AesCipherParams &&) noexcept = default;
    AesCipherParams &operator=(AesCipherParams &&) noexcept = default;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
    std::array<unsigned char, KEY_SIZE> key{};     // Encryption key
    std::array<unsigned char, IV_SIZE> iv{};       // Initialization vector
};

std::string ToHexString(std::span<const unsigned char> bytes) {
    std::stringstream hex;
    hex << std::hex << std::setfill('0');
    for (const unsigned char byte : bytes) {
        hex << std::setw(2) << static_cast<int>(byte);
    }
    return hex.str();
}

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() {
        ERR_clear_error();
        CheckOpenSslResult(OpenSSL_add_all_algorithms(), "failed to initialize OpenSSL");
    }
    ~Impl() { EVP_cleanup(); }

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;
    Impl(Impl &&) = delete;
    Impl &operator=(Impl &&) = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        Process(inStream, outStream, password, CIPHER_MODE::ENCRYPT);
    }
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        Process(inStream, outStream, password, CIPHER_MODE::DECRYPT);
    }
    std::string CalculateChecksum(std::iostream &inStream) {
        CheckInputStream(inStream);
        ERR_clear_error();

        const EvpMdCtxPtr ctx{CheckOpenSslResult(EVP_MD_CTX_new(), "failed to create a digest context")};
        CheckOpenSslResult(EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), nullptr),
                           "failed to initialize the SHA-256 digest");

        ForEachChunk(inStream, [&](std::span<const char> chunk) {
            CheckOpenSslResult(EVP_DigestUpdate(ctx.get(), chunk.data(), chunk.size()),
                               "failed to hash the input data");
        });

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digestLength = 0;
        CheckOpenSslResult(EVP_DigestFinal_ex(ctx.get(), digest.data(), &digestLength),
                           "failed to finalize the SHA-256 digest");

        return ToHexString(std::span{digest}.first(digestLength));
    }

private:
    // TODO :: To be reworked in the future
    static AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        if (password.empty()) {
            throw std::invalid_argument{"password must not be empty"};
        }
        if (!std::in_range<int>(password.size())) {
            throw std::invalid_argument{"password is too long"};
        }

        AesCipherParams params;
        constexpr std::array<unsigned char, 8> SALT = {'1', '2', '3', '4', '5', '6', '7', '8'};

        const int result = EVP_BytesToKey(params.cipher, EVP_sha256(), SALT.data(),
                                          reinterpret_cast<const unsigned char *>(password.data()),
                                          static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());
        if (result != static_cast<int>(AesCipherParams::KEY_SIZE)) {
            ThrowOpenSslError("failed to derive a key from the password");
        }
        return params;
    }

    static void Process(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                        CIPHER_MODE mode) {
        CheckStreams(inStream, outStream);
        ERR_clear_error();

        const bool encrypting = mode == CIPHER_MODE::ENCRYPT;
        const auto params = CreateCipherParamsFromPassword(password);

        const EvpCipherCtxPtr ctx{CheckOpenSslResult(EVP_CIPHER_CTX_new(), "failed to create a cipher context")};
        CheckOpenSslResult(EVP_CipherInit_ex2(ctx.get(), params.cipher, params.key.data(), params.iv.data(),
                                              std::to_underlying(mode), nullptr),
                           "failed to initialize the AES-256-CBC cipher");

        std::array<unsigned char, CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH> outBuffer{};
        int outLength = 0;

        ForEachChunk(inStream, [&](std::span<const char> chunk) {
            CheckOpenSslResult(EVP_CipherUpdate(ctx.get(), outBuffer.data(), &outLength,
                                                reinterpret_cast<const unsigned char *>(chunk.data()),
                                                static_cast<int>(chunk.size())),
                               encrypting ? "failed to encrypt the input data" : "failed to decrypt the input data");
            WriteChunk(outStream, std::span{outBuffer}.first(static_cast<std::size_t>(outLength)));
        });

        CheckOpenSslResult(EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &outLength),
                           encrypting ? "failed to finalize encryption"
                                      : "failed to decrypt: wrong password or corrupted input data");
        WriteChunk(outStream, std::span{outBuffer}.first(static_cast<std::size_t>(outLength)));
    }
};

CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    impl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    impl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return impl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
