# diverg-recon

Small Rust helper for the Python `recon` skill: **async TCP connect scans** and **concurrent DNS A lookups** (JSON over stdin/stdout). Invoked by [`skills/recon/recon.py`](../../skills/recon/recon.py); if the binary is absent, recon falls back to nmap + dnspython.

## Build

```bash
cd native/diverg-recon
cargo build --release
```

Optional: `export DIVERG_RECON_BIN=/path/to/diverg-recon`

## Usage

```bash
echo '{"host":"example.com","ports":[80,443],"deadline_ms":5000}' | ./target/release/diverg-recon ports
echo '{"domain":"example.com","prefixes":["www","api"],"deadline_ms":8000}' | ./target/release/diverg-recon dns-brute
```
