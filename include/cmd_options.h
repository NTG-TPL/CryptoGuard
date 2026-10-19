#pragma once

#include <boost/program_options/options_description.hpp>
#include <filesystem>
#include <iostream>
#include <string>

namespace CryptoGuard {

class ProgramOptions {
public:
    enum class COMMAND_TYPE {
        NONE,
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    enum class PARSE_RESULT {
        OK,
        HELP_SHOWN,
    };

    ProgramOptions();

    PARSE_RESULT Parse(int argc, char *argv[], std::ostream &helpOut = std::cout);

    COMMAND_TYPE GetCommand() const noexcept { return command_; }
    const std::filesystem::path &GetInputFile() const noexcept { return inputFile_; }
    const std::filesystem::path &GetOutputFile() const noexcept { return outputFile_; }
    const std::string &GetPassword() const noexcept { return password_; }

private:
    COMMAND_TYPE command_ = COMMAND_TYPE::NONE;
    std::filesystem::path inputFile_;
    std::filesystem::path outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
