.PHONY: build test test-real demo bench fmt clippy clean

CARGO ?= cargo
DEV_MODE ?= 0

build:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace --release

test-real:
	$(CARGO) test --workspace --release -- --ignored

demo:
	RISC0_DEV_MODE=$(DEV_MODE) ./scripts/demo.sh

bench:
	$(CARGO) build --release -p attestation-circuit --bin baseline
	RISC0_DEV_MODE=0 ./target/release/baseline

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --workspace -- -D warnings

clean:
	$(CARGO) clean
