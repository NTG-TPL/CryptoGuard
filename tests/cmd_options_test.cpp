#include "cmd_options.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using CryptoGuard::ProgramOptions;
using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;
using PARSE_RESULT = ProgramOptions::PARSE_RESULT;
using Args = std::vector<std::string>;

PARSE_RESULT Parse(ProgramOptions &options, Args args, std::ostream &helpOut) {
    args.insert(args.begin(), "CryptoGuard");
    std::vector<char *> argv;
    for (auto &arg : args) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);
    return options.Parse(static_cast<int>(args.size()), argv.data(), helpOut);
}

PARSE_RESULT Parse(ProgramOptions &options, Args args) {
    std::ostringstream helpOut;
    return Parse(options, std::move(args), helpOut);
}

std::string ParseError(Args args) {
    ProgramOptions options;
    try {
        Parse(options, std::move(args));
    } catch (const std::invalid_argument &e) {
        return e.what();
    }
    ADD_FAILURE() << "std::invalid_argument was not thrown";
    return {};
}

class TempFile {
public:
    explicit TempFile(std::string_view name) : path_(std::filesystem::temp_directory_path() / name) {
        std::ofstream{path_} << "data";
    }
    ~TempFile() {
        std::error_code error;
        std::filesystem::remove(path_, error);
    }

    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;

    const std::filesystem::path &Path() const { return path_; }

private:
    std::filesystem::path path_;
};

}  // namespace

TEST(ProgramOptions, CommandIsNoneBeforeParse) {
    const ProgramOptions options;
    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::NONE);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, ParsesEncryptWithShortOptions) {
    ProgramOptions options;
    ASSERT_EQ(Parse(options, {"-c", "encrypt", "-i", "in.txt", "-o", "out.txt", "-p", "secret"}), PARSE_RESULT::OK);
    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ParsesDecryptWithLongOptions) {
    ProgramOptions options;
    ASSERT_EQ(Parse(options, {"--command", "decrypt", "--input=in.txt", "--output", "out.txt", "--password=secret"}),
              PARSE_RESULT::OK);
    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ParsesChecksumWithInputOnly) {
    ProgramOptions options;
    ASSERT_EQ(Parse(options, {"--input", "in.txt", "--command", "checksum"}), PARSE_RESULT::OK);
    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, PrintsHelp) {
    for (const auto *flag : {"-h", "--help"}) {
        SCOPED_TRACE(flag);
        ProgramOptions options;
        std::ostringstream helpOut;

        ASSERT_EQ(Parse(options, {flag}, helpOut), PARSE_RESULT::HELP_SHOWN);

        const auto help = helpOut.str();
        for (const auto *expected :
             {"Usage", "--command", "--input", "--output", "--password", "--help", "encrypt", "decrypt", "checksum"}) {
            EXPECT_TRUE(help.contains(expected)) << "help does not mention " << expected;
        }
    }
}

TEST(ProgramOptions, HelpTakesPriorityOverOtherOptions) {
    ProgramOptions options;
    EXPECT_EQ(Parse(options, {"-c", "unknown", "--help"}), PARSE_RESULT::HELP_SHOWN);
    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::NONE);
}

TEST(ProgramOptions, RequiresCommand) {
    EXPECT_TRUE(ParseError({"-i", "in.txt"}).contains("--command"));
    EXPECT_TRUE(ParseError({}).contains("--command"));
}

TEST(ProgramOptions, RejectsUnknownCommand) {
    for (const auto *command : {"compress", "Encrypt"}) {
        SCOPED_TRACE(command);
        const auto error = ParseError({"-c", command, "-i", "in.txt"});
        EXPECT_TRUE(error.contains(command) && error.contains("encrypt, decrypt, checksum")) << error;
    }
}

TEST(ProgramOptions, RequiresInput) {
    for (const auto *command : {"encrypt", "decrypt", "checksum"}) {
        SCOPED_TRACE(command);
        EXPECT_TRUE(ParseError({"-c", command, "-o", "out.txt", "-p", "secret"}).contains("--input"));
    }
}

TEST(ProgramOptions, EncryptAndDecryptRequireOutputAndPassword) {
    for (const auto *command : {"encrypt", "decrypt"}) {
        SCOPED_TRACE(command);
        EXPECT_TRUE(ParseError({"-c", command, "-i", "in.txt", "-p", "secret"}).contains("--output"));
        EXPECT_TRUE(ParseError({"-c", command, "-i", "in.txt", "-o", "out.txt"}).contains("--password"));
    }
}

TEST(ProgramOptions, ChecksumRejectsOutputAndPassword) {
    EXPECT_TRUE(ParseError({"-c", "checksum", "-i", "in.txt", "-o", "out.txt"}).contains("--output"));
    EXPECT_TRUE(ParseError({"-c", "checksum", "-i", "in.txt", "-p", "secret"}).contains("--password"));
}

TEST(ProgramOptions, RejectsEmptyValues) {
    EXPECT_TRUE(ParseError({"-c", "", "-i", "in.txt"}).contains("--command"));
    EXPECT_TRUE(ParseError({"-c", "checksum", "-i", ""}).contains("--input"));
    EXPECT_TRUE(ParseError({"-c", "encrypt", "-i", "in.txt", "-o", "", "-p", "secret"}).contains("--output"));
    EXPECT_TRUE(ParseError({"-c", "encrypt", "-i", "in.txt", "-o", "out.txt", "-p", ""}).contains("--password"));
}

TEST(ProgramOptions, RejectsMalformedCommandLine) {
    const std::vector<Args> cases = {
        {"-c", "checksum", "-i", "in.txt", "extra"},
        {"-c", "checksum", "-i", "in.txt", "-i", "other.txt"},
        {"--comm", "checksum", "-i", "in.txt"},
    };
    for (std::size_t i = 0; i < cases.size(); ++i) {
        SCOPED_TRACE(testing::Message() << "case #" << i);
        ProgramOptions options;
        EXPECT_THROW(Parse(options, cases[i]), std::invalid_argument);
    }
}

TEST(ProgramOptions, RejectsSameInputAndOutputFile) {
    const TempFile input{"cryptoguard_cmd_options_test.txt"};
    const auto &path = input.Path();
    const auto samePathSpelledDifferently = path.parent_path() / "." / path.filename();

    for (const auto &output : {path, samePathSpelledDifferently}) {
        SCOPED_TRACE(output.string());
        const auto error = ParseError({"-c", "encrypt", "-i", path.string(), "-o", output.string(), "-p", "secret"});
        EXPECT_TRUE(error.contains("--input") && error.contains("--output")) << error;
    }
}

TEST(ProgramOptions, FailedParseKeepsPreviousState) {
    ProgramOptions options;
    ASSERT_EQ(Parse(options, {"-c", "encrypt", "-i", "in.txt", "-o", "out.txt", "-p", "secret"}), PARSE_RESULT::OK);

    EXPECT_THROW(Parse(options, {"-c", "decrypt", "-i", "other.txt", "-o", "other_out.txt"}), std::invalid_argument);

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}
