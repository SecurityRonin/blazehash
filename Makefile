.PHONY: setup check test lint fmt

setup:
	pre-commit install

check:
	pre-commit run --all-files

test:
	cargo test

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt --check
