ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SRC_DIR ?= $(ROOT)/tests/cache/src
BUILD_DIR ?= $(ROOT)/tests/cache/build
INSTALL_DIR ?= $(ROOT)/tests/cache/binutils
DOWNLOAD_URL_BASE ?= https://ftp.gnu.org/gnu/binutils
BINUTILS_VERSIONS ?= 2.26 2.30 2.34 2.42 2.43.1 2.44 2.45 2.46.0
ARCHIVE_EXTS ?= tar.xz tar.gz tar.bz2
BUILD_JOBS ?= 1

READELF_TARGETS := $(addsuffix /bin/readelf,$(addprefix $(INSTALL_DIR)/,$(BINUTILS_VERSIONS)))

.PHONY: all
all: $(READELF_TARGETS)

.SECONDARY: \
	$(addsuffix .archive,$(addprefix $(SRC_DIR)/binutils-,$(BINUTILS_VERSIONS))) \
	$(addsuffix .source,$(addprefix $(SRC_DIR)/binutils-,$(BINUTILS_VERSIONS))) \
	$(addsuffix /.configured,$(addprefix $(BUILD_DIR)/binutils-,$(BINUTILS_VERSIONS)))

$(SRC_DIR) $(BUILD_DIR) $(INSTALL_DIR):
	mkdir -p $@

$(SRC_DIR)/binutils-%.archive: | $(SRC_DIR)
	@set -e; \
	for ext in $(ARCHIVE_EXTS); do \
		archive="$(SRC_DIR)/binutils-$*.$$ext"; \
		if [ -f "$$archive" ]; then \
			touch "$@"; \
			exit 0; \
		fi; \
	done; \
	echo "downloading binutils-$*" >&2; \
	for ext in $(ARCHIVE_EXTS); do \
		archive="$(SRC_DIR)/binutils-$*.$$ext"; \
		url="$(DOWNLOAD_URL_BASE)/binutils-$*.$$ext"; \
		if command -v curl >/dev/null 2>&1; then \
			if curl -L --fail -o "$$archive" "$$url"; then \
				touch "$@"; \
				exit 0; \
			fi; \
		else \
			if wget -O "$$archive" "$$url"; then \
				touch "$@"; \
				exit 0; \
			fi; \
		fi; \
		rm -f "$$archive"; \
	done; \
	echo "failed to download binutils-$*" >&2; \
	exit 1

$(SRC_DIR)/binutils-%.source: $(SRC_DIR)/binutils-%.archive | $(SRC_DIR)
	@set -e; \
	rm -rf "$(SRC_DIR)/binutils-$*"; \
	for ext in $(ARCHIVE_EXTS); do \
		archive="$(SRC_DIR)/binutils-$*.$$ext"; \
		if [ -f "$$archive" ]; then \
			tar -xf "$$archive" -C "$(SRC_DIR)"; \
			touch "$@"; \
			exit 0; \
		fi; \
	done; \
	echo "missing archive for binutils-$*" >&2; \
	exit 1

$(BUILD_DIR)/binutils-%/.configured: $(SRC_DIR)/binutils-%.source | $(BUILD_DIR)
	rm -rf "$(BUILD_DIR)/binutils-$*"
	mkdir -p "$(BUILD_DIR)/binutils-$*"
	cd "$(BUILD_DIR)/binutils-$*" && \
		"$(SRC_DIR)/binutils-$*/configure" \
			--prefix="$(INSTALL_DIR)/$*" \
			--disable-nls \
			--disable-werror \
			--enable-deterministic-archives
	touch "$@"

$(INSTALL_DIR)/%/bin/readelf: $(BUILD_DIR)/binutils-%/.configured | $(INSTALL_DIR)
	@echo "building binutils-$*" >&2
	$(MAKE) -C "$(BUILD_DIR)/binutils-$*" -j"$(BUILD_JOBS)" all-binutils
	$(MAKE) -C "$(BUILD_DIR)/binutils-$*" install-binutils
