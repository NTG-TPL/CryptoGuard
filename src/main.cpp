#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include "output_file.h"

#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string_view>

namespace {

using CryptoGuard::CryptoGuardCtx;
using CryptoGuard::OutputFile;
using CryptoGuard::ProgramOptions;
using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;
using CryptoOperation = void (CryptoGuardCtx::*)(std::iostream &, std::iostream &, std::string_view);

std::fstream OpenInputFile(const std::filesystem::path &path) {
    std::fstream file{path, std::ios::in | std::ios::binary};
    if (!file.is_open()) {
        throw std::runtime_error{std::format("failed to open input file '{}'", path.string())};
    }
    return file;
}

void TransformFile(CryptoGuardCtx &ctx, CryptoOperation operation, const ProgramOptions &options) {
    auto input = OpenInputFile(options.GetInputFile());
    OutputFile output{options.GetOutputFile()};
    (ctx.*operation)(input, output.Stream(), options.GetPassword());
    output.Commit();
}

}  // namespace

int main(int argc, char *argv[]) {
    try {
        ProgramOptions options;
        try {
            if (options.Parse(argc, argv) == ProgramOptions::PARSE_RESULT::HELP_SHOWN) {
                return EXIT_SUCCESS;
            }
        } catch (const std::invalid_argument &e) {
            std::print(std::cerr, "Error: {}\nRun with --help to see the available options.\n", e.what());
            return EXIT_FAILURE;
        }

        CryptoGuardCtx cryptoCtx;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            TransformFile(cryptoCtx, &CryptoGuardCtx::EncryptFile, options);
            std::print("File encrypted successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            TransformFile(cryptoCtx, &CryptoGuardCtx::DecryptFile, options);
            std::print("File decrypted successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM: {
            auto input = OpenInputFile(options.GetInputFile());
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(input));
            break;
        }
        default:
            throw std::logic_error{"unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
