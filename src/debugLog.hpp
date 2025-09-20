#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace dns
{
namespace debug
{
#if defined(DNS_ENABLE_LOGGING)

inline constexpr bool kEnabled = true;

inline std::string timestamp()
{
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto timeT = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &timeT);
#else
    localtime_r(&timeT, &tm);
#endif
    const auto duration = now.time_since_epoch();
    const auto secondsPart = duration_cast<seconds>(duration);
    const auto microsPart = duration_cast<microseconds>(duration - secondsPart);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setw(6) << std::setfill('0') << microsPart.count();
    return oss.str();
}

inline std::string formatDuration(std::chrono::steady_clock::duration duration)
{
    using namespace std::chrono;
    const auto totalMicros = duration_cast<microseconds>(duration).count();

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3)
        << static_cast<double>(totalMicros) / 1000.0 << " ms ("
        << totalMicros << " us)";
    return oss.str();
}

inline void log(const std::string& component, const std::string& message)
{
    std::cout << '[' << timestamp() << "] [" << component << "] " << message << std::endl;
}

inline void logDuration(const std::string& component,
                        const std::string& activity,
                        std::chrono::steady_clock::duration duration)
{
    log(component, activity + " took " + formatDuration(duration));
}

#else

inline constexpr bool kEnabled = false;

inline std::string timestamp()
{
    return {};
}

inline std::string formatDuration(std::chrono::steady_clock::duration duration)
{
    (void)duration;
    return {};
}

inline void log(const std::string& component, const std::string& message)
{
    (void)component;
    (void)message;
}

inline void logDuration(const std::string& component,
                        const std::string& activity,
                        std::chrono::steady_clock::duration duration)
{
    (void)component;
    (void)activity;
    (void)duration;
}

#endif
} // namespace debug
} // namespace dns

