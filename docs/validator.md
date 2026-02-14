# Validator Guide

This guide explains how to run a Platform validator node on the Bittensor network.

## Key Features

- **No GPU required** - Validators run on standard CPU servers
- **No third-party APIs** - No OpenAI, Anthropic, or other API keys needed
- **One command setup** - Run `validator-node` directly
- **Minimal maintenance** - Set it and forget it

---

## P2P-Only Architecture

Platform validators run as a fully peer-to-peer network with no centralized fallback services. All validator-to-validator traffic happens over libp2p on port 9000, and consensus data is exchanged directly between peers.

- **Peer discovery**: Validators connect to the libp2p mesh and maintain a live peer set.
- **State sync**: Checkpoints, block proposals, and commits are shared only through the P2P network.
- **No central coordinator**: There are no HTTP relays or centralized aggregators for consensus.
- **Bittensor anchoring**: The metagraph provides stake and identity, but consensus payloads flow through P2P.

---

## Weight-Based Consensus Flow

Consensus is driven by validator weights derived from challenge evaluations. The validator set is stake-weighted, meaning higher-stake hotkeys carry more voting power when aggregating challenge results.

1. **Stake-weighted validator set**: Each validator’s voting power is proportional to its Bittensor stake in the metagraph. The active validator set is refreshed from the metagraph as epochs advance.
2. **Challenge evaluation**: Validators execute the active challenges, producing raw scores for miners or submissions.
3. **Commit-reveal weights**: Validators commit their weight vectors during the commit phase and reveal them in the reveal phase, preventing copycat behavior.
4. **Epoch boundary aggregation**: At the end of each epoch, revealed weights are aggregated using stake weighting to compute the canonical weight matrix.
5. **Consensus agreement**: Validators finalize the epoch by agreeing on the aggregated weights and resulting state hash over the P2P mesh.
6. **Weight submission**: The finalized weight matrix is submitted back to Bittensor as the subnet consensus output.

### Epoch Timeline

- **Commit window**: Validators broadcast weight commitments over libp2p.
- **Reveal window**: Validators reveal the committed weights to peers.
- **Aggregation window**: Stake-weighted aggregation finalizes the epoch weights and state hash.

---

## Quick start for validators

That's all you need to do:

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cp .env.example .env
# Edit .env: add your VALIDATOR_SECRET_KEY (BIP39 mnemonic)

# Start the validator directly (recommended)
mkdir -p data
cargo build --release --bin validator-node
./target/release/validator-node --data-dir ./data --secret-key "${VALIDATOR_SECRET_KEY}"

# Optional: install Docker + Compose for test harnesses only
./scripts/install-docker.sh
```

The validator will auto-connect to the network and sync. No GPUs, no third-party API keys, nothing else required.

---

## Requirements

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 4 vCPU | 8 vCPU |
| **RAM** | 16 GB | 32 GB |
| **Storage** | 250 GB SSD | 500 GB NVMe |
| **Network** | 100 Mbps | 100 Mbps |

> **Note**: Hardware requirements may increase over time as more challenges are added.

### Network

**Port 9000/tcp must be open** for P2P communication.

### Software

- Linux (Ubuntu 22.04+ recommended)

### Build Tooling (Nightly Parallel rustc + Fast Linker)

Validator development builds can take advantage of nightly parallel rustc and fast linkers.
Nightly defaults are enabled when using `rust-toolchain-nightly.toml` (it sets
`PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"`). If you opt into nightly with `RUSTUP_TOOLCHAIN=nightly`
or `cargo +nightly`, set the variable yourself.

Supported fast linkers:

- **Linux**: `mold`, `lld`
- **macOS**: `lld`, `zld`

```bash
export RUSTUP_TOOLCHAIN=nightly
export PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"

export PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=mold"
# export PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# macOS linker selection
# export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN="-C link-arg=-fuse-ld=lld"
# export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN="-C link-arg=-fuse-ld=zld"

cargo build
```

Opt out by unsetting `PLATFORM_NIGHTLY_RUSTFLAGS` or setting it to an empty string. To override defaults,
set `PLATFORM_LINKER_RUSTFLAGS` (Linux) or `PLATFORM_LINKER_RUSTFLAGS_DARWIN` (macOS).

### Bittensor

- **Minimum stake**: 1000 TAO
- Registered hotkey on subnet
- BIP39 mnemonic or hex private key

---

## Configuration Reference

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VALIDATOR_SECRET_KEY` | BIP39 mnemonic or hex private key | - | **Yes** |
| `SUBTENSOR_ENDPOINT` | Bittensor RPC endpoint | `wss://entrypoint-finney.opentensor.ai:443` | No |
| `NETUID` | Subnet UID | `100` | No |
| `RUST_LOG` | Log level (`debug`, `info`, `warn`, `error`) | `info` | No |

### Network Ports

| Port | Protocol | Usage | Required |
|------|----------|-------|----------|
| 9000/tcp | libp2p | P2P validator communication | **Yes** |
| 8545/tcp | HTTP | JSON-RPC API | No |

---

## Monitoring

### Check Validator Status

```bash
# View logs (if running directly)
tail -f ./data/validator.log
```

### JSON-RPC Health Check

```bash
curl -X POST http://localhost:8545/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","id":1}'
```

Expected response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "peers": 5,
    "is_synced": true,
    "block_height": 12345
  },
  "id": 1
}
```

### Key Log Messages

| Message | Meaning |
|---------|---------|
| `Bittensor hotkey: 5G...` | Successfully connected to Bittensor |
| `Synced metagraph: N neurons` | Metagraph loaded |
| `Block sync started` | Listening to Bittensor blocks |
| `DB in consensus` | Synchronized with other validators |
| `Mechanism weights submitted` | Weights sent to Bittensor |

---

## Testing and Validation

### Faster Local Builds (Optional)

The workspace defaults to using all CPU cores for builds (`build.jobs = "default"`). To override the
default, set `CARGO_BUILD_JOBS=8` (or any integer) before running `cargo build`.

To opt into nightly-only parallel rustc and a faster linker, set:

```bash
export RUSTUP_TOOLCHAIN=nightly
export PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"
export PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=mold"
```

Install a fast linker (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y mold
# or
sudo apt-get install -y lld
```

Validator test harnesses rely on Docker and Docker Compose. Docker is not required to run a production validator. The test harness automatically invokes `scripts/install-docker.sh` when Docker is missing (unless `PLATFORM_TEST_DOCKER_MODE=skip`).

- Run `./scripts/test-comprehensive.sh` to execute Docker-backed integration and multi-validator tests.
- Run `./scripts/test-all.sh` for build/unit-only runs (Docker not required).

---

## Troubleshooting

### Connection Issues

**Problem**: `Failed to connect to Bittensor`

```bash
# Check endpoint connectivity
curl -I wss://entrypoint-finney.opentensor.ai:443

# Try alternative endpoint
SUBTENSOR_ENDPOINT=wss://subtensor.api.opentensor.ai:443
```

**Problem**: `No peers connected`

```bash
# Verify port 9000 is open
sudo netstat -tlnp | grep 9000

# Check firewall
sudo ufw status
```

### Stake Issues

**Problem**: `Insufficient stake`

- Verify your hotkey has at least 1000 TAO staked
- Check you're using the correct mnemonic/key
- Ensure hotkey is registered on the correct subnet

### Docker Issues (tests only)

**Problem**: `Cannot connect to Docker daemon`

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart docker
sudo systemctl restart docker
```

### State Divergence

**Problem**: `DB DIVERGENCE detected`

This means your state differs from the majority. Usually resolves automatically:

1. Wait for automatic sync (up to 2 minutes)
2. If persistent, restart the validator:
   ```bash
   # Restart your validator process
   ```
3. If still diverged, reset state:
   ```bash
   rm -rf ./data/distributed-db
   ./target/release/validator-node --data-dir ./data --secret-key "${VALIDATOR_SECRET_KEY}"
   ```

---

## Security Best Practices

### Protect Your Keys

- Never share your mnemonic or private key
- Use environment variables, not command-line arguments
- Restrict `.env` file permissions:
  ```bash
  chmod 600 .env
  ```

### Network Security

- Use a firewall (ufw, iptables)
- Only expose required ports (9000)
- Consider running behind a reverse proxy for RPC

### System Security

- Keep system updated: `sudo apt update && sudo apt upgrade`
- Use SSH keys, disable password authentication
- Monitor system logs for anomalies

---

## Upgrading

Rebuild and restart the validator:

```bash
cargo build --release --bin validator-node
./target/release/validator-node --data-dir ./data --secret-key "${VALIDATOR_SECRET_KEY}"
```

---

## Stopping the Validator

Stop the validator process (CTRL+C or service manager). Remove data manually if needed:

```bash
rm -rf ./data/distributed-db
```

---

## Support

- **GitHub Issues**: [platform/issues](https://github.com/PlatformNetwork/platform/issues)
- **Discord**: Join our community for real-time support