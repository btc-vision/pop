#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <source_location>
#include <functional>
#include <vector>
#include <thread>
#include <condition_variable>
#include <queue>

namespace pop {

// ============================================================================
// Log Levels
// ============================================================================

enum class LogLevel : std::uint8_t {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5,
    OFF = 6,
};

[[nodiscard]] constexpr std::string_view log_level_name(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        case LogLevel::OFF:   return "OFF";
    }
    return "UNKNOWN";
}

[[nodiscard]] constexpr std::string_view log_level_color(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "\033[90m";    // Gray
        case LogLevel::DEBUG: return "\033[36m";    // Cyan
        case LogLevel::INFO:  return "\033[32m";    // Green
        case LogLevel::WARN:  return "\033[33m";    // Yellow
        case LogLevel::ERROR: return "\033[31m";    // Red
        case LogLevel::FATAL: return "\033[35;1m";  // Bright Magenta
        case LogLevel::OFF:   return "";
    }
    return "";
}

// ============================================================================
// Log Entry
// ============================================================================

struct LogEntry {
    LogLevel level;
    std::chrono::system_clock::time_point timestamp;
    std::thread::id thread_id;
    std::string component;
    std::string message;
    std::string file;
    std::uint32_t line;
    std::string function;
};

// ============================================================================
// Log Sink Interface
// ============================================================================

class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(const LogEntry& entry) = 0;
    virtual void flush() = 0;
};

// ============================================================================
// Console Log Sink
// ============================================================================

class ConsoleSink : public LogSink {
public:
    explicit ConsoleSink(bool use_colors = true);

    void write(const LogEntry& entry) override;
    void flush() override;

    void set_use_colors(bool use_colors) { use_colors_ = use_colors; }
    void set_show_thread_id(bool show) { show_thread_id_ = show; }
    void set_show_source_location(bool show) { show_source_location_ = show; }

private:
    bool use_colors_;
    bool show_thread_id_ = true;
    bool show_source_location_ = false;
    std::mutex mutex_;

    std::string format_entry(const LogEntry& entry) const;
};

// ============================================================================
// File Log Sink
// ============================================================================

class FileSink : public LogSink {
public:
    explicit FileSink(const std::string& filename);
    ~FileSink() override;

    void write(const LogEntry& entry) override;
    void flush() override;

    void set_max_file_size(std::size_t bytes) { max_file_size_ = bytes; }
    void set_max_files(std::size_t count) { max_files_ = count; }

private:
    std::string filename_;
    std::FILE* file_ = nullptr;
    std::size_t current_size_ = 0;
    std::size_t max_file_size_ = 100 * 1024 * 1024;  // 100MB
    std::size_t max_files_ = 5;
    std::mutex mutex_;

    void rotate_if_needed();
    void rotate();
};

// ============================================================================
// Async Log Sink Wrapper
// ============================================================================

class AsyncSink : public LogSink {
public:
    explicit AsyncSink(std::shared_ptr<LogSink> inner_sink, std::size_t queue_size = 10000);
    ~AsyncSink() override;

    void write(const LogEntry& entry) override;
    void flush() override;

    void start();
    void stop();

private:
    std::shared_ptr<LogSink> inner_sink_;
    std::queue<LogEntry> queue_;
    std::size_t max_queue_size_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_thread_;
    std::atomic<bool> running_{false};

    void worker_loop();
};

// ============================================================================
// Logger
// ============================================================================

class Logger {
public:
    static Logger& instance();

    // Configure logger
    void set_level(LogLevel level);
    void set_component_level(const std::string& component, LogLevel level);
    void add_sink(std::shared_ptr<LogSink> sink);
    void clear_sinks();

    // Check if level is enabled
    [[nodiscard]] bool is_enabled(LogLevel level, const std::string& component = "") const;

    // Log a message
    void log(LogLevel level,
             std::string_view component,
             std::string_view message,
             const std::source_location& loc = std::source_location::current());

    // Flush all sinks
    void flush();

    // Get current level
    [[nodiscard]] LogLevel level() const { return level_.load(); }

private:
    Logger();
    ~Logger();

    std::atomic<LogLevel> level_{LogLevel::INFO};
    std::unordered_map<std::string, LogLevel> component_levels_;
    std::vector<std::shared_ptr<LogSink>> sinks_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Log Stream Helper
// ============================================================================

class LogStream {
public:
    LogStream(LogLevel level,
              std::string_view component,
              const std::source_location& loc);
    ~LogStream();

    LogStream(const LogStream&) = delete;
    LogStream& operator=(const LogStream&) = delete;
    LogStream(LogStream&&) = default;
    LogStream& operator=(LogStream&&) = default;

    template<typename T>
    LogStream& operator<<(const T& value) {
        if (enabled_) {
            stream_ << value;
        }
        return *this;
    }

private:
    LogLevel level_;
    std::string component_;
    std::source_location loc_;
    std::ostringstream stream_;
    bool enabled_;
};

// ============================================================================
// Component Logger
// ============================================================================

class ComponentLogger {
public:
    explicit ComponentLogger(std::string component);

    [[nodiscard]] bool is_trace_enabled() const;
    [[nodiscard]] bool is_debug_enabled() const;
    [[nodiscard]] bool is_info_enabled() const;

    LogStream trace(const std::source_location& loc = std::source_location::current()) const;
    LogStream debug(const std::source_location& loc = std::source_location::current()) const;
    LogStream info(const std::source_location& loc = std::source_location::current()) const;
    LogStream warn(const std::source_location& loc = std::source_location::current()) const;
    LogStream error(const std::source_location& loc = std::source_location::current()) const;
    LogStream fatal(const std::source_location& loc = std::source_location::current()) const;

    void trace(std::string_view msg, const std::source_location& loc = std::source_location::current()) const;
    void debug(std::string_view msg, const std::source_location& loc = std::source_location::current()) const;
    void info(std::string_view msg, const std::source_location& loc = std::source_location::current()) const;
    void warn(std::string_view msg, const std::source_location& loc = std::source_location::current()) const;
    void error(std::string_view msg, const std::source_location& loc = std::source_location::current()) const;
    void fatal(std::string_view msg, const std::source_location& loc = std::source_location::current()) const;

private:
    std::string component_;
};

// ============================================================================
// Logging Macros
// ============================================================================

#define POP_LOG_TRACE(logger) \
    if ((logger).is_trace_enabled()) (logger).trace()

#define POP_LOG_DEBUG(logger) \
    if ((logger).is_debug_enabled()) (logger).debug()

#define POP_LOG_INFO(logger) \
    if ((logger).is_info_enabled()) (logger).info()

#define POP_LOG_WARN(logger) (logger).warn()

#define POP_LOG_ERROR(logger) (logger).error()

#define POP_LOG_FATAL(logger) (logger).fatal()

// ============================================================================
// Default Loggers for Core Components
// ============================================================================

namespace log {

// Core components
inline ComponentLogger core("core");
inline ComponentLogger crypto("crypto");
inline ComponentLogger consensus("consensus");
inline ComponentLogger state("state");
inline ComponentLogger execution("execution");
inline ComponentLogger network("network");

// Specific subsystems
inline ComponentLogger vdf("consensus.vdf");
inline ComponentLogger finality("consensus.finality");
inline ComponentLogger identity("consensus.identity");
inline ComponentLogger receipts("consensus.receipts");
inline ComponentLogger commit("consensus.commit");
inline ComponentLogger reveal("consensus.reveal");
inline ComponentLogger account("state.account");
inline ComponentLogger wasm("execution.wasm");

}  // namespace log

// ============================================================================
// Initialization Helper
// ============================================================================

struct LogConfig {
    LogLevel default_level = LogLevel::INFO;
    bool console_enabled = true;
    bool console_colors = true;
    bool console_thread_id = true;
    bool console_source_location = false;
    bool file_enabled = false;
    std::string file_path = "pop.log";
    std::size_t file_max_size = 100 * 1024 * 1024;
    std::size_t file_max_count = 5;
    bool async_logging = true;
};

void init_logging(const LogConfig& config = LogConfig{});
void shutdown_logging();

}  // namespace pop
