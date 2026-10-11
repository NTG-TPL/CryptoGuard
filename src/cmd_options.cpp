#include "cmd_options.h"
#include "option_info.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <format>
#include <print>
#include <ranges>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace CryptoGuard {

namespace {

namespace po = boost::program_options;
using namespace detail;
using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;
using CommandMapping = std::pair<std::string_view, COMMAND_TYPE>;

constexpr std::string_view kEncrypt = "encrypt";
constexpr std::string_view kDecrypt = "decrypt";
constexpr std::string_view kChecksum = "checksum";

constexpr std::array<CommandMapping, 3> kCommandMapping{{
    {kEncrypt, COMMAND_TYPE::ENCRYPT},
    {kDecrypt, COMMAND_TYPE::DECRYPT},
    {kChecksum, COMMAND_TYPE::CHECKSUM},
}};

std::string AllowedCommands() {
    return kCommandMapping | std::views::keys | std::views::join_with(std::string_view{", "}) |
           std::ranges::to<std::string>();
}

COMMAND_TYPE ToCommand(std::string_view name) {
    const auto it = std::ranges::find(kCommandMapping, name, &CommandMapping::first);
    if (it == kCommandMapping.end()) {
        throw std::invalid_argument{std::format("unknown command '{}', expected one of: {}", name, AllowedCommands())};
    }
    return it->second;
}

bool IsSet(const po::variables_map &vm, const OptionInfo &option) { return vm.count(option.Key()) > 0; }

std::string GetRequired(const po::variables_map &vm, const OptionInfo &option) {
    if (!IsSet(vm, option)) {
        throw std::invalid_argument{std::format("option '--{}' is required", option.longName)};
    }
    auto value = vm[option.Key()].as<std::string>();
    if (value.empty()) {
        throw std::invalid_argument{std::format("option '--{}' must not be empty", option.longName)};
    }
    return value;
}

void RejectOption(const po::variables_map &vm, const OptionInfo &option, std::string_view command) {
    if (IsSet(vm, option)) {
        throw std::invalid_argument{
            std::format("option '--{}' is not used with the '{}' command", option.longName, command)};
    }
}

bool IsSameFile(const std::filesystem::path &lhs, const std::filesystem::path &rhs) {
    std::error_code error;
    return std::filesystem::equivalent(lhs, rhs, error);
}

void PrintHelp(std::ostream &out, const po::options_description &desc) {
    std::print(out,
               "Usage:\n"
               "  CryptoGuard --{} {}|{} {} {} {}\n"
               "  CryptoGuard --{} {} {}\n\n",
               kCommand.longName, kEncrypt, kDecrypt, kInput.Usage(), kOutput.Usage(), kPassword.Usage(),
               kCommand.longName, kChecksum, kInput.Usage());
    out << desc << '\n';
}

void AddOption(po::options_description &desc, const OptionInfo &option) {
    const auto spec = option.Spec();
    if (option.valueName == nullptr) {
        desc.add_options()(spec.c_str(), option.description);
    } else {
        desc.add_options()(spec.c_str(), po::value<std::string>()->value_name(option.valueName), option.description);
    }
}

}  // namespace

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    for (const auto &option : kOptions) {
        AddOption(desc_, option);
    }
}

ProgramOptions::PARSE_RESULT ProgramOptions::Parse(int argc, char *argv[], std::ostream &helpOut) {
    po::variables_map vm;
    try {
        const po::positional_options_description noPositional;
        const auto style = po::command_line_style::unix_style ^ po::command_line_style::allow_guessing;
        po::store(po::command_line_parser(argc, argv).options(desc_).positional(noPositional).style(style).run(), vm);
        if (IsSet(vm, kHelp)) {
            PrintHelp(helpOut, desc_);
            return PARSE_RESULT::HELP_SHOWN;
        }
        po::notify(vm);
    } catch (const po::error &e) {
        throw std::invalid_argument{e.what()};
    }

    const auto commandName = GetRequired(vm, kCommand);
    const auto command = ToCommand(commandName);
    auto inputFile = GetRequired(vm, kInput);
    std::string outputFile;
    std::string password;

    if (command == COMMAND_TYPE::CHECKSUM) {
        RejectOption(vm, kOutput, commandName);
        RejectOption(vm, kPassword, commandName);
    } else {
        outputFile = GetRequired(vm, kOutput);
        password = GetRequired(vm, kPassword);
        if (IsSameFile(inputFile, outputFile)) {
            throw std::invalid_argument{std::format("options '--{}' and '--{}' must point to different files",
                                                    kInput.longName, kOutput.longName)};
        }
    }

    command_ = command;
    inputFile_ = std::move(inputFile);
    outputFile_ = std::move(outputFile);
    password_ = std::move(password);
    return PARSE_RESULT::OK;
}

}  // namespace CryptoGuard
