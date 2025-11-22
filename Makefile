# Makefile

PROJECT_NAME        := rusteth
LINUX_AMD64         := linux-amd64
LINUX_ARM           := linux-arm
LINUX_ARM64         := linux-arm64
TARGET_LINUX_AMD64  := x86_64-unknown-linux-musl
TARGET_LINUX_ARM    := armv7-unknown-linux-musleabihf
TARGET_LINUX_ARM64  := aarch64-unknown-linux-musl
CARGO_FLAGS         := --locked
CARGO_RELEASE_FLAGS := $(CARGO_FLAGS) --release
LINKER_MUSL         := rust-lld
LINKER_ARM          := $(LINKER_MUSL)
LINKER_ARM64        := $(LINKER_MUSL)
LINKER_WIN          := x86_64-w64-mingw32-gcc

all: build

.PHONY: build
build:
	@cargo build $(CARGO_FLAGS)

.PHONY: run
run:
	@cargo run -- --name Rust

.PHONY: release release-build release-archives
release: release-archives
release-build: $(LINUX_AMD64) $(LINUX_ARM) $(LINUX_ARM64)
release-archives: release-build
	@tar --gunzip --create --directory=target/$(TARGET_LINUX_AMD64)/release --file=./$(PROJECT_NAME)_$(LINUX_AMD64).tar.gz $(PROJECT_NAME)
	@tar --gunzip --create --directory=target/$(TARGET_LINUX_ARM)/release   --file=./$(PROJECT_NAME)_$(LINUX_ARM).tar.gz   $(PROJECT_NAME)
	@tar --gunzip --create --directory=target/$(TARGET_LINUX_ARM64)/release --file=./$(PROJECT_NAME)_$(LINUX_ARM64).tar.gz $(PROJECT_NAME)

$(LINUX_AMD64):
	@CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$(LINKER_MUSL) \
		cargo build $(CARGO_RELEASE_FLAGS) --target $(TARGET_LINUX_AMD64)
$(LINUX_ARM):
	@CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=$(LINKER_ARM) \
		cargo build $(CARGO_RELEASE_FLAGS) --target $(TARGET_LINUX_ARM)
$(LINUX_ARM64):
	@CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$(LINKER_ARM64) \
		cargo build $(CARGO_RELEASE_FLAGS) --target $(TARGET_LINUX_ARM64)

.PHONY: debug
debug:
	@RUST_LOG=debug cargo run -- --name Rust

.PHONY: fmt-check
fmt-check:
	@cargo fmt --all -- --check

.PHONY: clippy
clippy:
	@cargo clippy --all-targets -- -D warnings

.PHONY: audit
audit:
	@cargo audit

.PHONY: lint
lint: fmt-check clippy

.PHONY: test
test: lint build
	@cargo test --all

.PHONY: clean
clean:
	@cargo clean
