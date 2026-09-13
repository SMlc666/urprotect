# Reproducible native launcher build. The default toolchain is musl-gcc; on a
# host without it, callers must explicitly provide an AArch64 compiler, e.g.
# `make CC=aarch64-linux-gnu-gcc`.
SHELL := /bin/sh

ifeq ($(origin CC),default)
CC := musl-gcc
endif

BUILD_DIR ?= build
CC_BIN := $(firstword $(CC))
READELF ?= readelf
SOURCE_DATE_EPOCH ?= 0
MUSL_STATIC_PIE_SPECS ?= $(CURDIR)/musl-static-pie.specs
MUSL_BASE_SPECS ?= /usr/lib/aarch64-linux-musl/musl-gcc.specs
MUSL_REAL_CC ?= aarch64-linux-gnu-gcc
MUSL_MODE := $(findstring musl,$(CC))
ifneq ($(MUSL_MODE),)
MUSL_LINK_CC := $(MUSL_REAL_CC)
MUSL_LINK_SPECS := -specs=$(MUSL_BASE_SPECS) -specs=$(MUSL_STATIC_PIE_SPECS)
else
MUSL_LINK_CC := $(CC)
MUSL_LINK_SPECS :=
endif
MUSL_LINK_CC_BIN := $(firstword $(MUSL_LINK_CC))

CPPFLAGS := -I. -I../../third_party/miniz
CFLAGS := -std=c11 -O2 -g0 -fPIE -ffunction-sections -fdata-sections \
          -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector \
          -Wall -Wextra -Werror -Wshadow -Wconversion -Wstrict-prototypes
MINIZ_CPPFLAGS := -DMINIZ_NO_STDIO -DMINIZ_NO_TIME -DMINIZ_NO_DEFLATE_APIS \
                  -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_ZLIB_APIS \
                  -DMINIZ_NO_ZLIB_COMPATIBLE_NAMES -DMINIZ_NO_MALLOC \
                  -DMINIZ_LITTLE_ENDIAN=1 -DMINIZ_HAS_64BIT_REGISTERS=1 \
                  -DMINIZ_USE_UNALIGNED_LOADS_AND_STORES=0
MINIZ_CFLAGS := -std=c11 -O2 -g0 -fPIE -ffunction-sections -fdata-sections \
                -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector \
                -Wall -Wextra
# Older musl-gcc specs select Scrt1.o and add an interpreter; use the static
# PIE CRT fragment after the distribution specs and suppress that interpreter.
LDFLAGS := -static-pie -Wl,--no-dynamic-linker,--build-id=none,--gc-sections,-z,relro,-z,now -Wl,-s

LAUNCHER := $(BUILD_DIR)/urprotect-launcher
SELF_TEST := $(BUILD_DIR)/urprotect-launcher-self-test
LAUNCHER_OBJECTS := $(BUILD_DIR)/launcher_main.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/miniz_tinfl.o
SELF_TEST_OBJECTS := $(BUILD_DIR)/self_test.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/miniz_tinfl.o

.PHONY: all check-host check-elf launcher self-test provenance test clean

all: check-host launcher check-elf provenance

check-host:
	@host_arch="`uname -m`"; \
	if [ "$$host_arch" != "aarch64" ]; then \
		echo "native launcher requires an aarch64 host; got $$host_arch (QEMU/host substitution is not accepted)" >&2; \
		exit 2; \
	fi
	@if ! command -v "$(CC_BIN)" >/dev/null 2>&1; then \
		echo "AArch64 compiler '$(CC)' is unavailable; install musl-gcc or invoke make with an explicit CC=aarch64-linux-gnu-gcc override" >&2; \
		exit 127; \
	fi
	@if ! command -v "$(MUSL_LINK_CC_BIN)" >/dev/null 2>&1; then \
		echo "AArch64 link compiler '$(MUSL_LINK_CC)' is unavailable" >&2; \
		exit 127; \
	fi
	@target="`$(CC) -dumpmachine 2>/dev/null || true`"; \
	case "$$target" in *aarch64*) ;; *) \
		echo "compiler '$(CC)' targets '$$target', not AArch64" >&2; exit 2 ;; esac
	@if [ "$(MUSL_MODE)" != "" ]; then \
		target="`$(MUSL_LINK_CC) -dumpmachine 2>/dev/null || true`"; \
		case "$$target" in *aarch64*) ;; *) \
			echo "link compiler '$(MUSL_LINK_CC)' targets '$$target', not AArch64" >&2; exit 2 ;; esac; \
	fi

launcher: check-host $(LAUNCHER)

$(LAUNCHER): $(LAUNCHER_OBJECTS) $(MUSL_STATIC_PIE_SPECS)
	@mkdir -p "$(BUILD_DIR)"
	$(MUSL_LINK_CC) $(CFLAGS) $(MUSL_LINK_SPECS) $(LDFLAGS) $(LAUNCHER_OBJECTS) -o "$@"
	chmod 0755 "$@"

self-test: check-host $(SELF_TEST)

$(SELF_TEST): $(SELF_TEST_OBJECTS) $(MUSL_STATIC_PIE_SPECS)
	@mkdir -p "$(BUILD_DIR)"
	$(MUSL_LINK_CC) $(CFLAGS) $(MUSL_LINK_SPECS) $(LDFLAGS) $(SELF_TEST_OBJECTS) -o "$@"
	chmod 0755 "$@"

$(BUILD_DIR)/launcher_main.o: launcher_main.c sha256.h ../../third_party/miniz/miniz_tinfl.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/self_test.o: self_test.c sha256.h ../../third_party/miniz/miniz_tinfl.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/sha256.o: sha256.c sha256.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/miniz_tinfl.o: ../../third_party/miniz/miniz_tinfl.c \
	../../third_party/miniz/miniz.h ../../third_party/miniz/miniz_common.h \
	../../third_party/miniz/miniz_export.h ../../third_party/miniz/miniz_tdef.h \
	../../third_party/miniz/miniz_tinfl.h ../../third_party/miniz/miniz_zip.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(MINIZ_CPPFLAGS) $(MINIZ_CFLAGS) -c "$<" -o "$@"

check-elf: $(LAUNCHER)
	@file "$<"
	@grep -a -q 'URPROTECT-AARCH64-LAUNCHER-V1' "$<"
	@"$(READELF)" -hW "$<" | grep -q 'Class:.*ELF64'
	@"$(READELF)" -hW "$<" | grep -q 'Data:.*little endian'
	@"$(READELF)" -hW "$<" | grep -q 'Machine:.*AArch64'
	@"$(READELF)" -hW "$<" | grep -q 'Type:.*DYN'
	@if "$(READELF)" -lW "$<" | grep -q 'INTERP'; then \
		echo "launcher unexpectedly requires an interpreter" >&2; exit 1; \
	fi
	@if "$(READELF)" -dW "$<" | grep -q 'NEEDED'; then \
		echo "launcher unexpectedly has a shared-library dependency" >&2; exit 1; \
	fi

provenance: $(LAUNCHER)
	./provenance.sh "$(BUILD_DIR)/PROVENANCE.txt" "$(CC)" "$(LAUNCHER)" "$(SOURCE_DATE_EPOCH)" "$(MUSL_LINK_CC)" "$(MUSL_LINK_SPECS)" "$(MUSL_BASE_SPECS)"

test: check-host check-elf self-test
	"$(SELF_TEST)"
	./test_launcher.sh "$(LAUNCHER)"

clean:
	rm -rf "$(BUILD_DIR)"
