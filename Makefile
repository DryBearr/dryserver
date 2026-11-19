# The binary is copied into the installer ISO and onto every server, so it
# must be static: it is built for musl. Without a local musl target
# (rustup target add x86_64-unknown-linux-musl) it is built inside a Rust
# Alpine container with podman.
TARGET     := x86_64-unknown-linux-musl
RUST_IMAGE := docker.io/library/rust:1.99-alpine
SYSROOT    := $(shell rustc --print sysroot 2>/dev/null)
SOURCES    := $(shell find src assets -type f) Cargo.toml Cargo.lock build.rs

ifneq ($(wildcard $(SYSROOT)/lib/rustlib/$(TARGET)),)
dryserver: $(SOURCES)
	cargo build --release --locked --target $(TARGET)
	cp target/$(TARGET)/release/dryserver $@
else
dryserver: $(SOURCES)
	@echo "==> No local $(TARGET) target; building in $(RUST_IMAGE)"
	mkdir -p target/container-registry
	podman run --rm --security-opt label=disable \
		-v "$(CURDIR):/src" -w /src \
		-v "$(CURDIR)/target/container-registry:/usr/local/cargo/registry" \
		-e CARGO_TARGET_DIR=/src/target/container \
		$(RUST_IMAGE) cargo build --release --locked
	cp target/container/release/dryserver $@
endif

.PHONY: test
test:
	cargo test
