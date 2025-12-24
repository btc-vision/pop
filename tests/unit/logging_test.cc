#include <gtest/gtest.h>
#include "core/logging.hh"
#include <sstream>
#include <thread>

namespace pop {
namespace {

class LoggingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset to default state
    }
};

TEST_F(LoggingTest, LogLevelNames) {
    EXPECT_EQ(log_level_name(LogLevel::TRACE), "TRACE");
    EXPECT_EQ(log_level_name(LogLevel::DEBUG), "DEBUG");
    EXPECT_EQ(log_level_name(LogLevel::INFO), "INFO");
    EXPECT_EQ(log_level_name(LogLevel::WARN), "WARN");
    EXPECT_EQ(log_level_name(LogLevel::ERROR), "ERROR");
    EXPECT_EQ(log_level_name(LogLevel::FATAL), "FATAL");
    EXPECT_EQ(log_level_name(LogLevel::OFF), "OFF");
}

TEST_F(LoggingTest, LogLevelColors) {
    EXPECT_FALSE(log_level_color(LogLevel::TRACE).empty());
    EXPECT_FALSE(log_level_color(LogLevel::DEBUG).empty());
    EXPECT_FALSE(log_level_color(LogLevel::INFO).empty());
    EXPECT_FALSE(log_level_color(LogLevel::WARN).empty());
    EXPECT_FALSE(log_level_color(LogLevel::ERROR).empty());
    EXPECT_FALSE(log_level_color(LogLevel::FATAL).empty());
}

TEST_F(LoggingTest, LoggerSingleton) {
    Logger& logger1 = Logger::instance();
    Logger& logger2 = Logger::instance();
    EXPECT_EQ(&logger1, &logger2);
}

TEST_F(LoggingTest, LoggerSetLevel) {
    Logger& logger = Logger::instance();

    logger.set_level(LogLevel::DEBUG);
    EXPECT_EQ(logger.level(), LogLevel::DEBUG);

    logger.set_level(LogLevel::WARN);
    EXPECT_EQ(logger.level(), LogLevel::WARN);

    // Reset
    logger.set_level(LogLevel::INFO);
}

TEST_F(LoggingTest, LoggerIsEnabled) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::INFO);

    EXPECT_FALSE(logger.is_enabled(LogLevel::TRACE));
    EXPECT_FALSE(logger.is_enabled(LogLevel::DEBUG));
    EXPECT_TRUE(logger.is_enabled(LogLevel::INFO));
    EXPECT_TRUE(logger.is_enabled(LogLevel::WARN));
    EXPECT_TRUE(logger.is_enabled(LogLevel::ERROR));
    EXPECT_TRUE(logger.is_enabled(LogLevel::FATAL));
}

TEST_F(LoggingTest, ComponentLoggerBasic) {
    ComponentLogger logger("test");

    // These should not throw
    logger.info("Test info message");
    logger.warn("Test warn message");
    logger.error("Test error message");
}

TEST_F(LoggingTest, ComponentLoggerStream) {
    ComponentLogger logger("test");

    // Stream-based logging
    logger.info() << "Test message " << 42 << " with " << 3.14;
    logger.warn() << "Warning: " << "something happened";
}

TEST_F(LoggingTest, ComponentLoggerLevelCheck) {
    Logger::instance().set_level(LogLevel::WARN);

    ComponentLogger logger("test");

    EXPECT_FALSE(logger.is_trace_enabled());
    EXPECT_FALSE(logger.is_debug_enabled());
    EXPECT_FALSE(logger.is_info_enabled());

    Logger::instance().set_level(LogLevel::DEBUG);

    EXPECT_FALSE(logger.is_trace_enabled());
    EXPECT_TRUE(logger.is_debug_enabled());
    EXPECT_TRUE(logger.is_info_enabled());

    // Reset
    Logger::instance().set_level(LogLevel::INFO);
}

TEST_F(LoggingTest, ComponentLevelOverride) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::WARN);  // Global level

    // Override for specific component
    logger.set_component_level("test.debug", LogLevel::DEBUG);

    EXPECT_FALSE(logger.is_enabled(LogLevel::DEBUG, "other"));
    EXPECT_TRUE(logger.is_enabled(LogLevel::DEBUG, "test.debug"));
    EXPECT_TRUE(logger.is_enabled(LogLevel::WARN, "other"));

    // Reset
    logger.set_level(LogLevel::INFO);
}

TEST_F(LoggingTest, ParentComponentLevel) {
    Logger& logger = Logger::instance();
    logger.set_level(LogLevel::WARN);  // Global level

    // Set level for parent component
    logger.set_component_level("consensus", LogLevel::DEBUG);

    // Child components should inherit
    EXPECT_TRUE(logger.is_enabled(LogLevel::DEBUG, "consensus.vdf"));
    EXPECT_TRUE(logger.is_enabled(LogLevel::DEBUG, "consensus.finality"));

    // Other components should use global
    EXPECT_FALSE(logger.is_enabled(LogLevel::DEBUG, "execution"));

    // Reset
    logger.set_level(LogLevel::INFO);
}

TEST_F(LoggingTest, DefaultLoggers) {
    // Verify default loggers exist
    EXPECT_FALSE(log::core.is_trace_enabled());  // Default is INFO
    EXPECT_FALSE(log::crypto.is_trace_enabled());
    EXPECT_FALSE(log::consensus.is_trace_enabled());
    EXPECT_FALSE(log::state.is_trace_enabled());
    EXPECT_FALSE(log::execution.is_trace_enabled());
    EXPECT_FALSE(log::network.is_trace_enabled());
}

TEST_F(LoggingTest, LogEntryFields) {
    LogEntry entry;
    entry.level = LogLevel::INFO;
    entry.timestamp = std::chrono::system_clock::now();
    entry.thread_id = std::this_thread::get_id();
    entry.component = "test";
    entry.message = "Test message";
    entry.file = "test.cc";
    entry.line = 42;
    entry.function = "TestFunc";

    EXPECT_EQ(entry.level, LogLevel::INFO);
    EXPECT_EQ(entry.component, "test");
    EXPECT_EQ(entry.message, "Test message");
    EXPECT_EQ(entry.line, 42);
}

TEST_F(LoggingTest, LogConfigDefaults) {
    LogConfig config;

    EXPECT_EQ(config.default_level, LogLevel::INFO);
    EXPECT_TRUE(config.console_enabled);
    EXPECT_TRUE(config.console_colors);
    EXPECT_TRUE(config.console_thread_id);
    EXPECT_FALSE(config.console_source_location);
    EXPECT_FALSE(config.file_enabled);
    EXPECT_TRUE(config.async_logging);
}

TEST_F(LoggingTest, LogMacros) {
    ComponentLogger logger("test");

    // These macros should work without issues
    POP_LOG_INFO(logger) << "Info via macro";
    POP_LOG_WARN(logger) << "Warn via macro";
    POP_LOG_ERROR(logger) << "Error via macro";
}

TEST_F(LoggingTest, ThreadSafety) {
    Logger& logger = Logger::instance();
    std::atomic<int> completed{0};

    auto log_func = [&completed]() {
        ComponentLogger thread_logger("thread");
        for (int i = 0; i < 100; ++i) {
            thread_logger.info() << "Thread message " << i;
        }
        completed++;
    };

    // Launch multiple threads
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back(log_func);
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(completed.load(), 4);
}

}  // namespace
}  // namespace pop
