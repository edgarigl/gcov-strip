ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SRC_DIR ?= $(ROOT)/tests/cache/src
BUILD_DIR ?= $(ROOT)/tests/cache/build
INSTALL_DIR ?= $(ROOT)/tests/cache/binutils
DOWNLOAD_URL_BASE ?= https://ftp.gnu.org/gnu/binutils
BINUTILS_VERSIONS ?= 2.42 2.43.1 2.44 2.45 2.46.0
BUILD_JOBS ?= 1

READELF_TARGETS := $(addsuffix /bin/readelf,$(addprefix $(INSTALL_DIR)/,$(BINUTILS_VERSIONS)))

.PHONY: all
all: $(READELF_TARGETS)

$(SRC_DIR) $(BUILD_DIR) $(INSTALL_DIR):
	mkdir -p $@

$(SRC_DIR)/binutils-%.tar.xz: | $(SRC_DIR)
	@echo "downloading binutils-$*" >&2
	@if command -v curl >/dev/null 2>&1; then \
		curl -L --fail -o "$@" "$(DOWNLOAD_URL_BASE)/binutils-$*.tar.xz"; \
	else \
		wget -O "$@" "$(DOWNLOAD_URL_BASE)/binutils-$*.tar.xz"; \
	fi

$(SRC_DIR)/binutils-%: $(SRC_DIR)/binutils-%.tar.xz | $(SRC_DIR)
	tar -xf "$<" -C "$(SRC_DIR)"

$(BUILD_DIR)/binutils-%/.configured: $(SRC_DIR)/binutils-% | $(BUILD_DIR)
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
