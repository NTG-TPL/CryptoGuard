#include "cmd_options.h"

#include "option_info.h"

#include <algorithm>
#include <array>
#include <boost/program_options.hpp>
#include <filesystem>
#include <format>
#include <ostream>
#include <print>
#include <ranges>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace CryptoGuard {

using namespace detail;

namespace {

namespace PO = boost::program_options;
using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;

struct CommandEntry {
    std::string_view name;
    COMMAND_TYPE type;
};

constexpr std::string_view ENCRYPT_NAME = "encrypt";
constexpr std::string_view DECRYPT_NAME = "decrypt";
constexpr std::string_view CHECKSUM_NAME = "checksum";

constexpr auto COMMAND_MAPPING = std::to_array<CommandEntry>({
    {ENCRYPT_NAME, COMMAND_TYPE::ENCRYPT},
    {DECRYPT_NAME, COMMAND_TYPE::DECRYPT},
    {CHECKSUM_NAME, COMMAND_TYPE::CHECKSUM},
});

std::string AllowedCommands() {
    return COMMAND_MAPPING | std::views::transform(&CommandEntry::name) |
           std::views::join_with(std::string_view{", "}) | std::ranges::to<std::string>();
}

COMMAND_TYPE ToCommand(std::string_view name) {
    const auto it = std::ranges::find(COMMAND_MAPPING, name, &CommandEntry::name);
    if (it == COMMAND_MAPPING.end()) {
        throw std::invalid_argument{std::format("unknown command '{}', expected one of: {}", name, AllowedCommands())};
    }
    return it->type;
}

bool IsSet(const PO::variables_map &vm, const OptionInfo &option) { return vm.contains(option.Key()); }

std::string GetRequired(const PO::variables_map &vm, const OptionInfo &option) {
    if (!IsSet(vm, option)) {
        throw std::invalid_argument{std::format("option '--{}' is required", option.longName)};
    }
    auto value = vm[option.Key()].as<std::string>();
    if (value.empty()) {
        throw std::invalid_argument{std::format("option '--{}' must not be empty", option.longName)};
    }
    return value;
}

void RejectOption(const PO::variables_map &vm, const OptionInfo &option, std::string_view command) {
    if (IsSet(vm, option)) {
        throw std::invalid_argument{
            std::format("option '--{}' is not used with the '{}' command", option.longName, command)};
    }
}

bool IsSameFile(const std::filesystem::path &lhs, const std::filesystem::path &rhs) {
    std::error_code error;
    return std::filesystem::equivalent(lhs, rhs, error);
}

void PrintHelp(std::ostream &out, const PO::options_description &desc) {
    std::print(out,
               "Usage:\n"
               "  CryptoGuard --{} {}|{} {} {} {}\n"
               "  CryptoGuard --{} {} {}\n\n",
               COMMAND_OPTION.longName, ENCRYPT_NAME, DECRYPT_NAME, INPUT_OPTION.Usage(), OUTPUT_OPTION.Usage(),
               PASSWORD_OPTION.Usage(), COMMAND_OPTION.longName, CHECKSUM_NAME, INPUT_OPTION.Usage());
    out << desc << '\n';
}

void AddOption(PO::options_description &desc, const OptionInfo &option) {
    const auto spec = option.Spec();
    if (option.valueName) {
        desc.add_options()(spec.c_str(), PO::value<std::string>()->value_name(option.valueName), option.description);
    } else {
        desc.add_options()(spec.c_str(), option.description);
    }
}

}  // namespace

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    for (const auto &option : ALL_OPTIONS) {
        AddOption(desc_, option);
    }
}

ProgramOptions::PARSE_RESULT ProgramOptions::Parse(int argc, char *argv[], std::ostream &helpOut) {
    PO::variables_map vm;
    try {
        const PO::positional_options_description noPositional;
        PO::store(PO::command_line_parser(argc, argv).options(desc_).positional(noPositional).run(), vm);
        if (IsSet(vm, HELP_OPTION)) {
            PrintHelp(helpOut, desc_);
            return PARSE_RESULT::HELP_SHOWN;
        }
        PO::notify(vm);
    } catch (const PO::error &e) {
        throw std::invalid_argument{e.what()};
    }

    const auto commandName = GetRequired(vm, COMMAND_OPTION);
    const auto parsedCommand = ToCommand(commandName);
    std::filesystem::path parsedInputFile = GetRequired(vm, INPUT_OPTION);
    std::filesystem::path parsedOutputFile;
    std::string parsedPassword;

    if (parsedCommand == COMMAND_TYPE::CHECKSUM) {
        RejectOption(vm, OUTPUT_OPTION, commandName);
        RejectOption(vm, PASSWORD_OPTION, commandName);
    } else {
        parsedOutputFile = GetRequired(vm, OUTPUT_OPTION);
        parsedPassword = GetRequired(vm, PASSWORD_OPTION);
        if (IsSameFile(parsedInputFile, parsedOutputFile)) {
            throw std::invalid_argument{std::format("options '--{}' and '--{}' must point to different files",
                                                    INPUT_OPTION.longName, OUTPUT_OPTION.longName)};
        }
    }

    command_ = parsedCommand;
    inputFile_ = std::move(parsedInputFile);
    outputFile_ = std::move(parsedOutputFile);
    password_ = std::move(parsedPassword);
    return PARSE_RESULT::OK;
}

}  // namespace CryptoGuard
