#include "logging.hh"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <filesystem>

namespace pop {

// ============================================================================
// ConsoleSink Implementation
// ============================================================================

ConsoleSink::ConsoleSink(bool use_colors)
    : use_colors_(use_colors) {}

void ConsoleSink::write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cerr << format_entry(entry) << std::endl;
}

void ConsoleSink::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cerr.flush();
}

std::string ConsoleSink::format_entry(const LogEntry& entry) const {
    std::ostringstream oss;

    // Timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t);
#else
    localtime_r(&time_t, &tm_buf);
#endif

    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    // Thread ID
    if (show_thread_id_) {
        oss << " [" << entry.thread_id << "]";
    }

    // Level with color
    if (use_colors_) {
        oss << " " << log_level_color(entry.level);
    }
    oss << " [" << std::setw(5) << log_level_name(entry.level) << "]";
    if (use_colors_) {
        oss << "\033[0m";  // Reset color
    }

    // Component
    if (!entry.component.empty()) {
        oss << " [" << entry.component << "]";
    }

    // Message
    oss << " " << entry.message;

    // Source location
    if (show_source_location_ && !entry.file.empty()) {
        oss << " (" << entry.file << ":" << entry.line << ")";
    }

    return oss.str();
}

// ============================================================================
// FileSink Implementation
// ============================================================================

FileSink::FileSink(const std::string& filename)
    : filename_(filename) {
    file_ = std::fopen(filename.c_str(), "a");
    if (file_) {
        std::fseek(file_, 0, SEEK_END);
        current_size_ = static_cast<std::size_t>(std::ftell(file_));
    }
}

FileSink::~FileSink() {
    if (file_) {
        std::fclose(file_);
    }
}

void FileSink::write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!file_) {
        return;
    }

    rotate_if_needed();

    std::ostringstream oss;

    // Timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t);
#else
    localtime_r(&time_t, &tm_buf);
#endif

    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    // Thread ID
    oss << " [" << entry.thread_id << "]";

    // Level
    oss << " [" << std::setw(5) << log_level_name(entry.level) << "]";

    // Component
    if (!entry.component.empty()) {
        oss << " [" << entry.component << "]";
    }

    // Message
    oss << " " << entry.message;

    // Source location
    if (!entry.file.empty()) {
        oss << " (" << entry.file << ":" << entry.line << " " << entry.function << ")";
    }

    oss << "\n";

    std::string line = oss.str();
    std::fwrite(line.c_str(), 1, line.size(), file_);
    current_size_ += line.size();
}

void FileSink::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        std::fflush(file_);
    }
}

void FileSink::rotate_if_needed() {
    if (current_size_ >= max_file_size_) {
        rotate();
    }
}

void FileSink::rotate() {
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }

    // Rotate files
    namespace fs = std::filesystem;

    // Remove oldest file if exists
    std::string oldest = filename_ + "." + std::to_string(max_files_);
    if (fs::exists(oldest)) {
        fs::remove(oldest);
    }

    // Rotate existing files
    for (std::size_t i = max_files_ - 1; i >= 1; --i) {
        std::string src = filename_ + "." + std::to_string(i);
        std::string dst = filename_ + "." + std::to_string(i + 1);
        if (fs::exists(src)) {
            fs::rename(src, dst);
        }
    }

    // Rename current file
    if (fs::exists(filename_)) {
        fs::rename(filename_, filename_ + ".1");
    }

    // Open new file
    file_ = std::fopen(filename_.c_str(), "w");
    current_size_ = 0;
}

// ============================================================================
// AsyncSink Implementation
// ============================================================================

AsyncSink::AsyncSink(std::shared_ptr<LogSink> inner_sink, std::size_t queue_size)
    : inner_sink_(std::move(inner_sink))
    , max_queue_size_(queue_size) {}

AsyncSink::~AsyncSink() {
    stop();
}

void AsyncSink::write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (queue_.size() >= max_queue_size_) {
        // Drop oldest entry
        queue_.pop();
    }

    queue_.push(entry);
    cv_.notify_one();
}

void AsyncSink::flush() {
    // Wait for queue to drain
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]() { return queue_.empty() || !running_.load(); });

    if (inner_sink_) {
        inner_sink_->flush();
    }
}

void AsyncSink::start() {
    if (running_.exchange(true)) {
        return;  // Already running
    }
    worker_thread_ = std::thread(&AsyncSink::worker_loop, this);
}

void AsyncSink::stop() {
    running_.store(false);
    cv_.notify_all();

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    // Flush remaining entries
    while (!queue_.empty()) {
        inner_sink_->write(queue_.front());
        queue_.pop();
    }
    inner_sink_->flush();
}

void AsyncSink::worker_loop() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(mutex_);

        cv_.wait(lock, [this]() {
            return !queue_.empty() || !running_.load();
        });

        while (!queue_.empty()) {
            LogEntry entry = std::move(queue_.front());
            queue_.pop();
            lock.unlock();

            inner_sink_->write(entry);

            lock.lock();
        }
    }
}

// ============================================================================
// Logger Implementation
// ============================================================================

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

Logger::Logger() {
    // Default: console sink
    add_sink(std::make_shared<ConsoleSink>(true));
}

Logger::~Logger() {
    flush();
}

void Logger::set_level(LogLevel level) {
    level_.store(level);
}

void Logger::set_component_level(const std::string& component, LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    component_levels_[component] = level;
}

void Logger::add_sink(std::shared_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sinks_.push_back(std::move(sink));
}

void Logger::clear_sinks() {
    std::lock_guard<std::mutex> lock(mutex_);
    sinks_.clear();
}

bool Logger::is_enabled(LogLevel level, const std::string& component) const {
    // Check component-specific level first
    if (!component.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check exact match
        auto it = component_levels_.find(component);
        if (it != component_levels_.end()) {
            return level >= it->second;
        }

        // Check parent components (e.g., "consensus" for "consensus.vdf")
        std::string parent = component;
        while (true) {
            auto pos = parent.rfind('.');
            if (pos == std::string::npos) {
                break;
            }
            parent = parent.substr(0, pos);
            it = component_levels_.find(parent);
            if (it != component_levels_.end()) {
                return level >= it->second;
            }
        }
    }

    return level >= level_.load();
}

void Logger::log(LogLevel level,
                 std::string_view component,
                 std::string_view message,
                 const std::source_location& loc) {

    if (!is_enabled(level, std::string(component))) {
        return;
    }

    LogEntry entry;
    entry.level = level;
    entry.timestamp = std::chrono::system_clock::now();
    entry.thread_id = std::this_thread::get_id();
    entry.component = std::string(component);
    entry.message = std::string(message);
    entry.file = loc.file_name();
    entry.line = loc.line();
    entry.function = loc.function_name();

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& sink : sinks_) {
        sink->write(entry);
    }
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& sink : sinks_) {
        sink->flush();
    }
}

// ============================================================================
// LogStream Implementation
// ============================================================================

LogStream::LogStream(LogLevel level,
                     std::string_view component,
                     const std::source_location& loc)
    : level_(level)
    , component_(component)
    , loc_(loc)
    , enabled_(Logger::instance().is_enabled(level, std::string(component))) {}

LogStream::~LogStream() {
    if (enabled_ && !stream_.str().empty()) {
        Logger::instance().log(level_, component_, stream_.str(), loc_);
    }
}

// ============================================================================
// ComponentLogger Implementation
// ============================================================================

ComponentLogger::ComponentLogger(std::string component)
    : component_(std::move(component)) {}

bool ComponentLogger::is_trace_enabled() const {
    return Logger::instance().is_enabled(LogLevel::TRACE, component_);
}

bool ComponentLogger::is_debug_enabled() const {
    return Logger::instance().is_enabled(LogLevel::DEBUG, component_);
}

bool ComponentLogger::is_info_enabled() const {
    return Logger::instance().is_enabled(LogLevel::INFO, component_);
}

LogStream ComponentLogger::trace(const std::source_location& loc) const {
    return LogStream(LogLevel::TRACE, component_, loc);
}

LogStream ComponentLogger::debug(const std::source_location& loc) const {
    return LogStream(LogLevel::DEBUG, component_, loc);
}

LogStream ComponentLogger::info(const std::source_location& loc) const {
    return LogStream(LogLevel::INFO, component_, loc);
}

LogStream ComponentLogger::warn(const std::source_location& loc) const {
    return LogStream(LogLevel::WARN, component_, loc);
}

LogStream ComponentLogger::error(const std::source_location& loc) const {
    return LogStream(LogLevel::ERROR, component_, loc);
}

LogStream ComponentLogger::fatal(const std::source_location& loc) const {
    return LogStream(LogLevel::FATAL, component_, loc);
}

void ComponentLogger::trace(std::string_view msg, const std::source_location& loc) const {
    Logger::instance().log(LogLevel::TRACE, component_, msg, loc);
}

void ComponentLogger::debug(std::string_view msg, const std::source_location& loc) const {
    Logger::instance().log(LogLevel::DEBUG, component_, msg, loc);
}

void ComponentLogger::info(std::string_view msg, const std::source_location& loc) const {
    Logger::instance().log(LogLevel::INFO, component_, msg, loc);
}

void ComponentLogger::warn(std::string_view msg, const std::source_location& loc) const {
    Logger::instance().log(LogLevel::WARN, component_, msg, loc);
}

void ComponentLogger::error(std::string_view msg, const std::source_location& loc) const {
    Logger::instance().log(LogLevel::ERROR, component_, msg, loc);
}

void ComponentLogger::fatal(std::string_view msg, const std::source_location& loc) const {
    Logger::instance().log(LogLevel::FATAL, component_, msg, loc);
}

// ============================================================================
// Initialization
// ============================================================================

void init_logging(const LogConfig& config) {
    Logger& logger = Logger::instance();
    logger.clear_sinks();
    logger.set_level(config.default_level);

    if (config.console_enabled) {
        auto console = std::make_shared<ConsoleSink>(config.console_colors);
        console->set_show_thread_id(config.console_thread_id);
        console->set_show_source_location(config.console_source_location);

        if (config.async_logging) {
            auto async = std::make_shared<AsyncSink>(console);
            async->start();
            logger.add_sink(async);
        } else {
            logger.add_sink(console);
        }
    }

    if (config.file_enabled) {
        auto file = std::make_shared<FileSink>(config.file_path);
        file->set_max_file_size(config.file_max_size);
        file->set_max_files(config.file_max_count);

        if (config.async_logging) {
            auto async = std::make_shared<AsyncSink>(file);
            async->start();
            logger.add_sink(async);
        } else {
            logger.add_sink(file);
        }
    }

    log::core.info("Logging initialized");
}

void shutdown_logging() {
    log::core.info("Logging shutting down");
    Logger::instance().flush();
}

}  // namespace pop
