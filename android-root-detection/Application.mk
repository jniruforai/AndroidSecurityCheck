# Application.mk for Native Root Detection Library
# This file configures the native build for multiple architectures

# Target all common Android architectures
APP_ABI := arm64-v8a armeabi-v7a x86 x86_64

# Use the latest NDK platform
APP_PLATFORM := android-21

# Use C++17 standard
APP_STL := c++_shared
APP_CPPFLAGS := -std=c++17

# Enable all compiler optimizations for release
APP_OPTIM := release

# Security and optimization flags
APP_CFLAGS := -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
APP_CPPFLAGS += -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
APP_LDFLAGS := -Wl,-z,relro -Wl,-z,now -pie

# Strip debug symbols in release
APP_STRIP_MODE := --strip-unneeded

# Enable advanced security features
APP_CFLAGS += -ffunction-sections -fdata-sections
APP_LDFLAGS += -Wl,--gc-sections

# Hardening flags
APP_CFLAGS += -Wformat -Wformat-security -Wall -Wextra
APP_CPPFLAGS += -Wformat -Wformat-security -Wall -Wextra

# Control flow integrity (if supported)
APP_CFLAGS += -fcf-protection=full
APP_CPPFLAGS += -fcf-protection=full

# Enable position independent executable
APP_PIE := true