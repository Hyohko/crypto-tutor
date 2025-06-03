/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
*/
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