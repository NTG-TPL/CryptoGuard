#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <array>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <format>
#include <functional>
#include <ios>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace {

using CryptoGuard::CryptoGuardCtx;

constexpr std::size_t BLOCK_SIZE = 16;

struct ReferenceVector {
    std::string_view plaintext;
    std::string_view password;
    std::string_view ciphertextHex;
};

constexpr auto REFERENCE_VECTORS = std::to_array<ReferenceVector>({
    {"Hello OpenSSL crypto world!", "1234", "9b636bafae1e135b77da3843a723e1e64b8af3c3511c116e8eccd79c0159276d"},
    {"", "1234", "0a552eaefba8490bf50315836a9b515a"},
    {"0123456789abcdef", "1234", "91ef74c89fada9756e353c8144846ce88a86fa687364ba5f55deedf2920b1d66"},
    {"x", "other", "0be5434c99b3e4b61abb66ba423567da"},
});

using CryptoOperation = void (CryptoGuardCtx::*)(std::iostream &, std::iostream &, std::string_view);

struct NamedOperation {
    std::string_view name;
    CryptoOperation operation;
    std::string_view validInputHex;
};

constexpr auto OPERATIONS = std::to_array<NamedOperation>({
    {"EncryptFile", &CryptoGuardCtx::EncryptFile, "48656c6c6f20776f726c64212048656c6c6f20776f726c6421"},
    {"DecryptFile", &CryptoGuardCtx::DecryptFile, REFERENCE_VECTORS[0].ciphertextHex},
});

std::string ToHex(std::string_view bytes) {
    std::string hex;
    for (const unsigned char byte : bytes) {
        hex += std::format("{:02x}", byte);
    }
    return hex;
}

std::string FromHex(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument{std::format("hex string '{}' has odd length", hex)};
    }
    std::string bytes;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const auto *const first = hex.data() + i;
        const auto *const last = first + 2;
        unsigned value = 0;
        const auto [end, error] = std::from_chars(first, last, value, 16);
        if (error != std::errc{} || end != last) {
            throw std::invalid_argument{std::format("hex string '{}' has an invalid byte at {}", hex, i)};
        }
        bytes.push_back(static_cast<char>(value));
    }
    return bytes;
}

std::string Run(CryptoOperation operation, std::string_view input, std::string_view password) {
    CryptoGuardCtx ctx;
    std::stringstream in{std::string{input}};
    std::stringstream out;
    std::invoke(operation, ctx, in, out, password);
    return out.str();
}

std::string Encrypt(std::string_view plaintext, std::string_view password) {
    return Run(&CryptoGuardCtx::EncryptFile, plaintext, password);
}

std::string Decrypt(std::string_view ciphertext, std::string_view password) {
    return Run(&CryptoGuardCtx::DecryptFile, ciphertext, password);
}

std::string DecryptError(CryptoGuardCtx &ctx, std::string_view ciphertext, std::string_view password) {
    std::stringstream in{std::string{ciphertext}};
    std::stringstream out;
    try {
        ctx.DecryptFile(in, out, password);
    } catch (const std::runtime_error &e) {
        return e.what();
    }
    ADD_FAILURE() << "expected std::runtime_error was not thrown";
    return {};
}

std::string Checksum(CryptoGuardCtx &ctx, std::string_view data) {
    std::stringstream in{std::string{data}};
    return ctx.CalculateChecksum(in);
}

std::string Checksum(std::string_view data) {
    CryptoGuardCtx ctx;
    return Checksum(ctx, data);
}

std::string BinaryData(std::size_t size) {
    std::string data(size, '\0');
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<char>(i * 31 % 256);
    }
    return data;
}

class BrokenStreambuf : public std::streambuf {
protected:
    int_type overflow(int_type) override { return traits_type::eof(); }
    int_type underflow() override { throw std::ios_base::failure{"device error"}; }
};

}  // namespace

TEST(CryptoGuardCtx, IsMoveOnly) {
    static_assert(!std::is_copy_constructible_v<CryptoGuardCtx>);
    static_assert(!std::is_copy_assignable_v<CryptoGuardCtx>);
    static_assert(std::is_nothrow_move_constructible_v<CryptoGuardCtx>);
    static_assert(std::is_nothrow_move_assignable_v<CryptoGuardCtx>);
}

TEST(CryptoGuardCtx, SupportsMoveConstructionAndAssignment) {
    const auto expected = Checksum("abc");

    CryptoGuardCtx original;
    CryptoGuardCtx moved{std::move(original)};
    EXPECT_EQ(Checksum(moved, "abc"), expected);

    CryptoGuardCtx assigned;
    assigned = std::move(moved);
    EXPECT_EQ(Checksum(assigned, "abc"), expected);
}

TEST(CryptoGuardCtx, EncryptMatchesOpenSslReference) {
    for (const auto &[plaintext, password, ciphertextHex] : REFERENCE_VECTORS) {
        SCOPED_TRACE(std::format("plaintext '{}', password '{}'", plaintext, password));
        EXPECT_EQ(ToHex(Encrypt(plaintext, password)), ciphertextHex);
    }
}

TEST(CryptoGuardCtx, EncryptHandlesInputLargerThanInternalBuffer) {
    struct Case {
        std::size_t size;
        std::string_view expectedLastBlockHex;
    };
    const auto cases = std::to_array<Case>({
        {8192, "cc43b5243693884b7bc2419dd3326fea"},
        {10000, "340bf29f3839ff535b8659d1530c712a"},
    });
    for (const auto &[size, expectedLastBlockHex] : cases) {
        SCOPED_TRACE(std::format("size {}", size));
        const auto ciphertext = Encrypt(std::string(size, 'a'), "1234");
        ASSERT_EQ(ciphertext.size(), (size / BLOCK_SIZE + 1) * BLOCK_SIZE);
        EXPECT_EQ(ToHex(std::string_view{ciphertext}.substr(ciphertext.size() - BLOCK_SIZE)), expectedLastBlockHex);
    }
}

TEST(CryptoGuardCtx, DecryptMatchesOpenSslReference) {
    for (const auto &[plaintext, password, ciphertextHex] : REFERENCE_VECTORS) {
        SCOPED_TRACE(std::format("plaintext '{}', password '{}'", plaintext, password));
        EXPECT_EQ(Decrypt(FromHex(ciphertextHex), password), plaintext);
    }
}

TEST(CryptoGuardCtx, DecryptRestoresEncryptedData) {
    for (const auto size : {0uz, 1uz, 15uz, 16uz, 17uz, 4095uz, 4096uz, 4097uz, 10000uz}) {
        SCOPED_TRACE(std::format("size {}", size));
        const auto plaintext = BinaryData(size);
        EXPECT_EQ(Decrypt(Encrypt(plaintext, "1234"), "1234"), plaintext);
    }
}

TEST(CryptoGuardCtx, DecryptFailsWithWrongPassword) {
    const auto ciphertext = FromHex(REFERENCE_VECTORS[0].ciphertextHex);
    CryptoGuardCtx ctx;
    const auto message = DecryptError(ctx, ciphertext, "4321");
    EXPECT_TRUE(message.contains("wrong password")) << message;
    EXPECT_TRUE(message.contains("bad decrypt")) << message;
}

TEST(CryptoGuardCtx, ErrorMessageIgnoresStaleOpenSslErrors) {
    const auto ciphertext = FromHex(REFERENCE_VECTORS[0].ciphertextHex);
    CryptoGuardCtx ctx;
    ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);

    const auto message = DecryptError(ctx, ciphertext.substr(0, ciphertext.size() - 1), "1234");
    EXPECT_TRUE(message.contains("wrong final block length")) << message;
    EXPECT_FALSE(message.contains("bad decrypt")) << message;
}

TEST(CryptoGuardCtx, DecryptRejectsCorruptedCiphertext) {
    const auto ciphertext = FromHex(REFERENCE_VECTORS[0].ciphertextHex);
    for (const auto &corrupted : {ciphertext.substr(0, ciphertext.size() - 1), std::string{}}) {
        SCOPED_TRACE(std::format("{} bytes", corrupted.size()));
        ASSERT_THROW(Decrypt(corrupted, "1234"), std::runtime_error);
    }
}

TEST(CryptoGuardCtx, EncryptAndDecryptRequireReadyStreams) {
    for (const auto &[name, operation, validInputHex] : OPERATIONS) {
        SCOPED_TRACE(name);
        CryptoGuardCtx ctx;
        {
            std::stringstream in{FromHex(validInputHex)};
            std::stringstream out;
            in.setstate(std::ios::eofbit);
            ASSERT_THROW(std::invoke(operation, ctx, in, out, "1234"), std::runtime_error);
            EXPECT_TRUE(out.str().empty());
        }
        {
            std::stringstream in{FromHex(validInputHex)};
            std::stringstream out;
            out.setstate(std::ios::badbit);
            ASSERT_THROW(std::invoke(operation, ctx, in, out, "1234"), std::runtime_error);
            EXPECT_TRUE(in.good());
            EXPECT_EQ(in.tellg(), 0);
        }
    }
}

TEST(CryptoGuardCtx, EncryptAndDecryptRejectSameStreamForInputAndOutput) {
    for (const auto &[name, operation, validInputHex] : OPERATIONS) {
        SCOPED_TRACE(name);
        CryptoGuardCtx ctx;
        std::stringstream stream{FromHex(validInputHex)};
        ASSERT_THROW(std::invoke(operation, ctx, stream, stream, "1234"), std::invalid_argument);
    }
}

TEST(CryptoGuardCtx, EncryptAndDecryptRejectEmptyPassword) {
    for (const auto &[name, operation, validInputHex] : OPERATIONS) {
        SCOPED_TRACE(name);
        CryptoGuardCtx ctx;
        std::stringstream in{FromHex(validInputHex)};
        std::stringstream out;
        ASSERT_THROW(std::invoke(operation, ctx, in, out, ""), std::invalid_argument);
    }
}

TEST(CryptoGuardCtx, EncryptAndDecryptReportStreamFailuresDuringProcessing) {
    for (const auto &[name, operation, validInputHex] : OPERATIONS) {
        SCOPED_TRACE(name);
        CryptoGuardCtx ctx;
        BrokenStreambuf broken;
        {
            std::iostream in{&broken};
            std::stringstream out;
            ASSERT_THROW(std::invoke(operation, ctx, in, out, "1234"), std::runtime_error);
        }
        {
            std::stringstream in{FromHex(validInputHex)};
            std::iostream out{&broken};
            ASSERT_THROW(std::invoke(operation, ctx, in, out, "1234"), std::runtime_error);
        }
    }
}

TEST(CryptoGuardCtx, ChecksumMatchesSha256Reference) {
    struct Case {
        std::string_view data;
        std::string_view expectedHex;
    };
    const auto cases = std::to_array<Case>({
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"Hello OpenSSL crypto world!", "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899"},
    });
    for (const auto &[data, expectedHex] : cases) {
        SCOPED_TRACE(std::format("data '{}'", data));
        EXPECT_EQ(Checksum(data), expectedHex);
    }
}

TEST(CryptoGuardCtx, ChecksumHandlesInputLargerThanInternalBuffer) {
    EXPECT_EQ(Checksum(std::string(1'000'000, 'a')),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(CryptoGuardCtx, ChecksumRejectsUnreadableInput) {
    CryptoGuardCtx ctx;
    {
        std::stringstream in{"data"};
        in.setstate(std::ios::eofbit);
        ASSERT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
    }
    {
        BrokenStreambuf broken;
        std::iostream in{&broken};
        ASSERT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
    }
}

TEST(CryptoGuardCtx, ChecksumIsPreservedByEncryptDecryptRoundTrip) {
    const auto original = BinaryData(10000);
    const auto ciphertext = Encrypt(original, "1234");
    const auto restored = Decrypt(ciphertext, "1234");

    EXPECT_NE(Checksum(ciphertext), Checksum(original));
    EXPECT_EQ(Checksum(restored), Checksum(original));
}
