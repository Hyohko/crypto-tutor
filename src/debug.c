#include "debug.h"
#include <time.h>

#ifdef DEBUG
// Log level strings
static const char* level_strings[] = {
    "VERBOSE",
    "INFO",
    "WARN",
    "ERROR",
    "CRITICAL"
};

// ANSI color codes for terminal output
#define COLOR_RESET     "\x1b[0m"
#define COLOR_CYAN      "\x1b[36m"
#define COLOR_GREEN     "\x1b[32m"
#define COLOR_YELLOW    "\x1b[33m"
#define COLOR_RED       "\x1b[31m"
#define COLOR_MAGENTA   "\x1b[35m"

// Map log levels to color codes
static const char* level_colors[] = {
    COLOR_CYAN,     // VERBOSE
    COLOR_GREEN,    // INFO
    COLOR_YELLOW,   // WARN
    COLOR_RED,      // ERROR
    COLOR_MAGENTA   // CRITICAL
};

void debug_log(int level, const char* file, int line, const char* fmt, ...) {
    if (level < DEBUG_LEVEL_VERBOSE || level > DEBUG_LEVEL_CRITICAL)
        return;

    // Get current time
    time_t t = time(NULL);
    struct tm* lt = localtime(&t);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", lt);

    // Select color and log level string
    const char* color = level_colors[level];
    const char* level_str = level_strings[level];

    // Print the colored log message
    fprintf(stderr, "%s[%s] [%s] (%s:%d): ", color, time_str, level_str, file, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "%s\n", COLOR_RESET); // Reset color and end line
}
#endif // DEBUG