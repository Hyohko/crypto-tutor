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
#ifndef DEBUG_H
#define DEBUG_H

#include <stdarg.h>
#include <stdio.h>

// Define log levels
#define DEBUG_LEVEL_VERBOSE  0
#define DEBUG_LEVEL_INFO     1
#define DEBUG_LEVEL_WARN     2
#define DEBUG_LEVEL_ERROR    3
#define DEBUG_LEVEL_CRITICAL 4

#ifdef DEBUG

// Macro declarations for different debug levels
#define LOG_VERBOSE(...)                                                 \
    do {                                                                 \
        debug_log(DEBUG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)
#define LOG_INFO(...)                                                 \
    do {                                                              \
        debug_log(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)
#define LOG_WARN(...)                                                 \
    do {                                                              \
        debug_log(DEBUG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)
#define LOG_ERROR(...)                                                 \
    do {                                                               \
        debug_log(DEBUG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)
#define LOG_CRITICAL(...)                                                 \
    do {                                                                  \
        debug_log(DEBUG_LEVEL_CRITICAL, __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)

#else

// If DEBUG is not defined, strip all logging
#define LOG_VERBOSE(...) \
    do {                 \
    } while (0)
#define LOG_INFO(...) \
    do {              \
    } while (0)
#define LOG_WARN(...) \
    do {              \
    } while (0)
#define LOG_ERROR(...) \
    do {               \
    } while (0)
#define LOG_CRITICAL(...) \
    do {                  \
    } while (0)

#endif

// Function prototype
void debug_log(int level, const char* file, int line, const char* fmt, ...);

#endif  // DEBUG_H