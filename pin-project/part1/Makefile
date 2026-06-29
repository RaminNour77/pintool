# Makefile for part1.cpp

# Compiler
CXX = g++

# Source files
SRCS = part1.cpp

# Output executable
TARGET = part1

# Build target
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) -o $(TARGET) $(SRCS)

# Clean target
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean
