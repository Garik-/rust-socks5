.PHONY: fmt lint test run dev

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

run:
	cargo run

dev:
	curl --socks5 127.0.0.1:7878 https://habr.ru

