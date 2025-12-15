# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
PKG_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
LDFLAGS = -mwindows -Wl,-subsystem,windows
PKG_LIBS = $(shell pkg-config --libs gtk+-3.0) -lssl -lcrypto -lole32 -luser32 -lgdi32 -mwindows

# Source files
SRC = gui.c auth.c Encryption.c logging.c Manager.c
OBJ = $(addprefix build/obj/,$(SRC:.c=.o))
TARGET = build/bin/password_manager.exe

# Create build directories if they don't exist
build_dirs:
	@mkdir -p build/obj
	@mkdir -p build/bin

# Default target
all: build_dirs $(TARGET)

# Run the program from the bin directory
run: all
	@echo "Running $(TARGET)"
	@cd build/bin && ./password_manager.exe

# Link object files
$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(PKG_LIBS)

# Compile .c files to .o files in build/obj directory
build/obj/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -mwindows -c $< -o $@

# Clean up - only remove files, not directories
clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean run build_dirs
