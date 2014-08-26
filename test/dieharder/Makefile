# Inspired by (https://github.com/mbcrawfo/GenericMakefile)
BIN_NAME := main

C_SOURCES = \
       src/main.c

SRC_EXT = c
SRC_PATH = src
COMPILE_FLAGS = -std=c99 -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual
COMPILE_FLAGS += -Wno-missing-braces
#COMPILE_FLAGS = -Wconversion -Wsign-conversion
RCOMPILE_FLAGS = -O3
DCOMPILE_FLAGS = -g
INCLUDES = -I../../inc -Isrc -I../../deps/strong-arm/include/
LINK_FLAGS = -ltitan_secure_volume -lstrong-arm
RLINK_FLAGS = -O3
DLINK_FLAGS = -g


# Target
TARGET ?= linux

# Build and output paths
RBUILD_PATH = build/$(TARGET)/release
DBUILD_PATH = build/$(TARGET)/debug

DLINK_FLAGS += -L../../build/$(TARGET)/debug/ -L../../deps/strong-arm/build/$(TARGET)/debug/
RLINK_FLAGS += -L../../build/$(TARGET)/release/ -L../../deps/strong-arm/build/$(TARGET)/release/

ifeq ($(TARGET),linux)
	CC = gcc
	OBJCOPY = objcopy
	AR = ar
else ifeq ($(TARGET),cygwin_mingw)
	CC=i686-pc-mingw32-gcc
	OBJCOPY=i686-pc-mingw32-objcopy
	AR=i686-pc-mingw32-ar
else
$(error "TARGET must be set, e.g. make TARGET=linux")
endif


# Verbose option, to output compile and link commands
export V = false
export CMD_PREFIX = @
ifeq ($(V),true)
	CMD_PREFIX =
endif

# Combine compiler and linker flags
RCCFLAGS = $(CCFLAGS) $(COMPILE_FLAGS) $(RCOMPILE_FLAGS)
RLDFLAGS = $(LDFLAGS) $(LINK_FLAGS) $(RLINK_FLAGS)
DCCFLAGS = $(CCFLAGS) $(COMPILE_FLAGS) $(DCOMPILE_FLAGS)
DLDFLAGS = $(LDFLAGS) $(LINK_FLAGS) $(DLINK_FLAGS)

# Set the object file names, with the source directory stripped
# from the path, and the build path prepended in its place
DOBJECTS := $(C_SOURCES:%.c=$(DBUILD_PATH)/%.o)
DOBJECTS := $(DOBJECTS:%.s=$(DBUILD_PATH)/%.o)
ROBJECTS := $(C_SOURCES:%.c=$(RBUILD_PATH)/%.o)
ROBJECTS := $(ROBJECTS:%.s=$(RBUILD_PATH)/%.o)

# Set the dependency files that will be used to add header dependencies
DDEPS = $(DOBJECTS:.o=.d)
RDEPS = $(ROBJECTS:.o=.d)

# Main rule
all: dirs $(DBUILD_PATH)/$(BIN_NAME) $(RBUILD_PATH)/$(BIN_NAME)

# Create the directories used in the build
.PHONY: dirs
dirs:
	@echo "Creating directories"
	@mkdir -p $(dir $(DOBJECTS))
	@mkdir -p $(dir $(ROBJECTS))

# Link the executable
$(DBUILD_PATH)/$(BIN_NAME): $(DOBJECTS)
	@echo "Linking: $@"
	$(CMD_PREFIX)$(CC) $(DOBJECTS) $(DLDFLAGS) -o $@

$(RBUILD_PATH)/$(BIN_NAME): $(ROBJECTS)
	@echo "Linking: $@"
	$(CMD_PREFIX)$(CC) $(ROBJECTS) $(RLDFLAGS) -o $@

# Add dependency files, if they exist
-include $(DDEPS)
-include $(RDEPS)

# Source file rules
# After the first compilation they will be joined with the rules from the
# dependency files to provide header dependencies
$(DBUILD_PATH)/%.o: %.c
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(DBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(DCCFLAGS) $(INCLUDES) -I$(DBUILD_PATH) -MP -MMD -c $< -o $@

$(DBUILD_PATH)/%.o: %.s
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(DBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(DCCFLAGS) $(INCLUDES) -I$(DBUILD_PATH) -MP -MMD -c $< -o $@

$(RBUILD_PATH)/%.o: %.c
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(RBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(RCCFLAGS) $(INCLUDES) -I$(RBUILD_PATH) -MP -MMD -c $< -o $@

$(RBUILD_PATH)/%.o: %.s
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(RBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(RCCFLAGS) $(INCLUDES) -I$(RBUILD_PATH) -MP -MMD -c $< -o $@



.PHONE: clean
clean:
	@echo "Deleting directories"
	@$(RM) -r build
