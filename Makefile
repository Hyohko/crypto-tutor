# Compiler and flags
CC = gcc
# Add -g for debugging tests if needed
CFLAGS = -Wall -O3 -march=native -mtune=native -flto -DDEBUG -Isrc/unity -Isrc

# Directories
SRC_DIR = src
BUILD_DIR = build
UNITY_DIR = $(SRC_DIR)/unity
TEST_DIR = $(SRC_DIR)/test

# Source files
# Core sources used by both main app and tests
CORE_SRCS = $(SRC_DIR)/rsa.c $(SRC_DIR)/debug.c

# Main application specific sources
MAIN_APP_ONLY_SRCS = $(SRC_DIR)/main.c

# All sources for the main application
MAIN_APP_SRCS = $(MAIN_APP_ONLY_SRCS) $(CORE_SRCS)

# Unity framework source
UNITY_LIB_SRC = $(UNITY_DIR)/unity.c

# Test runner and individual test files
TEST_RUNNER_SRC = $(TEST_DIR)/test_runner.c
TEST_IMPL_SRCS = $(wildcard $(TEST_DIR)/test_*.c)

# All sources for the test executable
# Order matters for some linkers if there are dependencies, but usually not for .c files to .o
TEST_SRCS = $(TEST_RUNNER_SRC) $(TEST_IMPL_SRCS) $(CORE_SRCS) $(UNITY_LIB_SRC)

# Object files
# Need to handle object files for sources in subdirectories (like unity.c) correctly.
# One way is to have them all land flat in BUILD_DIR.
MAIN_APP_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MAIN_APP_ONLY_SRCS)) \
                $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))

TEST_OBJS = $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.o,$(TEST_RUNNER_SRC)) \
            $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.o,$(TEST_IMPL_SRCS)) \
            $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS)) \
            $(patsubst $(UNITY_DIR)/%.c,$(BUILD_DIR)/%.o,$(UNITY_LIB_SRC))


# Output binaries
TARGET_MAIN_APP = $(BUILD_DIR)/crypto-tutor
TARGET_TEST = $(BUILD_DIR)/test_runner

# Include system GMP headers and link system GMP library
INCLUDES = # Unity path is now in CFLAGS
LIBS = -lgmp -lm # Add -lm if math functions are used by Unity or tests

# Default target
all: $(TARGET_MAIN_APP)

# Build main application
$(TARGET_MAIN_APP): $(MAIN_APP_OBJS)
	@echo "Linking main application executable..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo "Main application build complete: $@"

# Test target: build and run tests
test: $(TARGET_TEST)
	@echo "Executing tests..."
	./$(TARGET_TEST)

# Build test runner executable
$(TARGET_TEST): $(TEST_OBJS)
	@echo "Linking test executable..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo "Test executable build complete: $@"

# Compile source files from SRC_DIR (e.g. src/main.c, src/rsa.c, src/test_*.c)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Compile source files from UNITY_DIR (e.g. src/unity/unity.c)
# This rule specifically handles unity.c from its subdirectory.
$(BUILD_DIR)/%.o: $(UNITY_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Create build directory if it doesn't exist
$(BUILD_DIR):
	@echo "Creating build directory: $(BUILD_DIR)"
	mkdir -p $(BUILD_DIR)

# Clean build files
clean:
	@echo "Cleaning build directory..."
	rm -rf $(BUILD_DIR)
	@echo "Clean complete."

.PHONY: all clean test
