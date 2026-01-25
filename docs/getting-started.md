# getting started

## installation
install via cargo:
```bash
cargo install --path crates/sbom-diff
```

## first diff
1. get two sboms (e.g., `old.json` and `new.json`).
2. run the diff:
```bash
sbom-diff old.json new.json
```

## next steps
- check [usage.md](usage.md) for cli flags.
- see [architecture.md](architecture.md) for internal details.
- browse [api.md](api.md) for library usage.
