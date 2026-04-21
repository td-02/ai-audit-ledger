# Contributing

Thanks for contributing to AI Audit Ledger.

## Development setup

### Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- Go toolchain (Go 1.23+)

### Clone and build

```bash
git clone https://github.com/td-02/ai-audit-ledger.git
cd ai-audit-ledger
cargo build --workspace
go build -buildvcs=false ./...
```

### Local verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
go test ./...
go build -buildvcs=false ./...
```

## Pull request guidelines

- Keep changes focused and small.
- Add tests for behavior changes.
- Update docs when user-facing behavior changes.
- Use descriptive commit messages.

## Reporting bugs and requesting features

Use GitHub issue templates in `.github/ISSUE_TEMPLATE/`.

