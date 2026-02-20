.PHONY: fmt lint test run dev speed-check build build-aarch64 install-aarch64-target

AARCH64_TARGET ?= aarch64-unknown-linux-gnu
PROXY_ADDR ?= 127.0.0.1:7878
CHECK_URL ?= https://habr.ru

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

run:
	TP_LOG_LEVEL=debug cargo run

dev:
	curl --socks5 $(PROXY_ADDR) $(CHECK_URL)

build:
	cargo build --release

install-aarch64-target:
	rustup target add $(AARCH64_TARGET)

build-aarch64: install-aarch64-target
	cargo build --release --target $(AARCH64_TARGET)
