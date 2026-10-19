#pragma once

#include <array>
#include <format>
#include <string>

namespace CryptoGuard::detail {

struct OptionInfo {
    const char *longName = nullptr;
    char shortName = '\0';
    const char *valueName = nullptr;
    const char *description = nullptr;

    std::string Key() const { return longName; }
    std::string Spec() const { return std::format("{},{}", longName, shortName); }
    std::string Usage() const { return std::format("-{} <{}>", shortName, longName); }
};

inline constexpr OptionInfo HELP_OPTION{
    .longName = "help",
    .shortName = 'h',
    .description = "show this help message",
};
inline constexpr OptionInfo COMMAND_OPTION{
    .longName = "command",
    .shortName = 'c',
    .valueName = "name",
    .description = "command to execute",
};
inline constexpr OptionInfo INPUT_OPTION{
    .longName = "input",
    .shortName = 'i',
    .valueName = "path",
    .description = "path to the input file",
};
inline constexpr OptionInfo OUTPUT_OPTION{
    .longName = "output",
    .shortName = 'o',
    .valueName = "path",
    .description = "path to the output file",
};
inline constexpr OptionInfo PASSWORD_OPTION{
    .longName = "password",
    .shortName = 'p',
    .valueName = "text",
    .description = "password for encryption and decryption",
};

inline constexpr std::array ALL_OPTIONS{HELP_OPTION, COMMAND_OPTION, INPUT_OPTION, OUTPUT_OPTION, PASSWORD_OPTION};

}  // namespace CryptoGuard::detail
