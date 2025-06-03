#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdarg.h>

// Define log levels
#define DEBUG_LEVEL_VERBOSE  0
#define DEBUG_LEVEL_INFO     1
#define DEBUG_LEVEL_WARN     2
#define DEBUG_LEVEL_ERROR    3
#define DEBUG_LEVEL_CRITICAL 4

#ifdef DEBUG

// Macro declarations for different debug levels
#define LOG_VERBOSE(...)   do { debug_log(DEBUG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__); } while (0)
#define LOG_INFO(...)      do { debug_log(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__); } while (0)
#define LOG_WARN(...)      do { debug_log(DEBUG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__); } while (0)
#define LOG_ERROR(...)     do { debug_log(DEBUG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__); } while (0)
#define LOG_CRITICAL(...)  do { debug_log(DEBUG_LEVEL_CRITICAL, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#else

// If DEBUG is not defined, strip all logging
#define LOG_VERBOSE(...)  do {} while (0)
#define LOG_INFO(...)     do {} while (0)
#define LOG_WARN(...)     do {} while (0)
#define LOG_ERROR(...)    do {} while (0)
#define LOG_CRITICAL(...) do {} while (0)

#endif

// Function prototype
void debug_log(int level, const char* file, int line, const char* fmt, ...);

#endif // DEBUG_H