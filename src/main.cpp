#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <cstdlib>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        try {
            if (options.Parse(argc, argv) == CryptoGuard::ProgramOptions::PARSE_RESULT::HELP_SHOWN) {
                return EXIT_SUCCESS;
            }
        } catch (const std::invalid_argument &e) {
            std::print(std::cerr, "Error: {}\nRun with --help to see the available options.\n", e.what());
            return EXIT_FAILURE;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
