.PHONY: check test fmt fmt-check clippy ci clean

check:
	cargo check --workspace --all-targets --all-features

test:
	cargo test --workspace --all-targets --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

ci: fmt-check check test clippy

clean:
	cargo clean
