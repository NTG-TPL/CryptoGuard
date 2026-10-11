#pragma once

#include <array>
#include <format>
#include <string>

namespace CryptoGuard::detail {

struct OptionInfo {
    const char *longName;
    char shortName;
    const char *valueName = nullptr;
    const char *description;

    std::string Key() const { return longName; }
    std::string Spec() const { return std::format("{},{}", longName, shortName); }
    std::string Usage() const { return std::format("-{} <{}>", shortName, longName); }
};

inline constexpr OptionInfo kHelp{
    .longName = "help",
    .shortName = 'h',
    .description = "show this help message",
};
inline constexpr OptionInfo kCommand{
    .longName = "command",
    .shortName = 'c',
    .valueName = "name",
    .description = "command to execute",
};
inline constexpr OptionInfo kInput{
    .longName = "input",
    .shortName = 'i',
    .valueName = "path",
    .description = "path to the input file",
};
inline constexpr OptionInfo kOutput{
    .longName = "output",
    .shortName = 'o',
    .valueName = "path",
    .description = "path to the output file",
};
inline constexpr OptionInfo kPassword{
    .longName = "password",
    .shortName = 'p',
    .valueName = "text",
    .description = "password for encryption and decryption",
};

inline constexpr std::array kOptions{kHelp, kCommand, kInput, kOutput, kPassword};

}  // namespace CryptoGuard::detail
