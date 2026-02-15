<div align="center">

# ρlατfοrm

**Distributed validator network for decentralized AI evaluation on Bittensor**

[![CI](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml/badge.svg)](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml)
[![Coverage](https://platformnetwork.github.io/platform/badges/coverage.svg)](https://github.com/PlatformNetwork/platform/actions)
[![License](https://img.shields.io/github/license/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/stargazers)
[![Rust](https://img.shields.io/badge/rust-1.90+-orange.svg)](https://www.rust-lang.org/)

![Platform Banner](assets/banner.jpg)

![Alt](https://repobeats.axiom.co/api/embed/4b44b7f7c97e0591af537309baea88689aefe810.svg "Repobeats analytics image")

</div>

---

## Introduction

**Platform** is a decentralized evaluation framework that enables trustless assessment of miner submissions through configurable challenges on the Bittensor network. By connecting multiple validators through a Byzantine fault-tolerant consensus mechanism, Platform ensures honest and reproducible evaluation while preventing gaming and manipulation.

> **Want to run a validator?** See the [Validator Guide](docs/validator.md) for setup instructions.

### Key Features

- **Fully Decentralized**: P2P architecture using libp2p gossipsub and DHT
- **Decentralized Evaluation**: Multiple validators independently evaluate submissions
- **Challenge-Based Architecture**: Modular sandboxed runtimes define custom evaluation logic
- **Byzantine Fault Tolerance**: PBFT consensus with $2f+1$ threshold ensures correctness
- **Secure Weight Submission**: Weights submitted to Bittensor at epoch boundaries
- **Multi-Mechanism Support**: Each challenge maps to a Bittensor mechanism for independent weight setting
- **Stake-Weighted Security**: Minimum 1000 TAO stake required for validator participation

---

## Rust Toolchain

This repository targets the Rust 2021 edition and defaults to the stable toolchain via `rust-toolchain.toml`.
To opt into nightly (for parallel rustc or other nightly-only features), use one of the following:

- `RUSTUP_TOOLCHAIN=nightly cargo build`
- `cargo +nightly build`
- `rustup override set nightly` inside the repo

If you prefer explicit file selection, temporarily copy or symlink `rust-toolchain-nightly.toml` to
`rust-toolchain.toml`. Stable builds do not enable nightly-only flags globally.

### Faster Builds (Parallel rustc + Fast Linker)

The repository ships with `.cargo/config.toml` configured to use all available CPU cores for compilation
(`build.jobs = "default"`). Override this locally with `CARGO_BUILD_JOBS=8` (or any integer) when you want
a smaller build footprint.

Nightly-only parallel rustc is enabled by default when you use the nightly toolchain file
(`rust-toolchain-nightly.toml`). It sets `PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"`, which lets nightly
use all CPU threads. If you opt into nightly via `RUSTUP_TOOLCHAIN=nightly` or `cargo +nightly`, set
`PLATFORM_NIGHTLY_RUSTFLAGS` yourself (for example, `-Z threads=0` or `-Z threads=8`). Opt out by
unsetting `PLATFORM_NIGHTLY_RUSTFLAGS` (or setting it to an empty string). The
`scripts/verify-nightly-config.sh`, `scripts/test-all.sh`, and `scripts/test-comprehensive.sh` helpers also
honor `PLATFORM_DISABLE_NIGHTLY=1` for an explicit opt-out, and accept `PLATFORM_RUST_NIGHTLY=1` to force
nightly toolchains during scripted runs.

Fast linker support is opt-in via environment variables; if you leave these unset,
Rust falls back to the system linker. Supported linkers:

- **Linux**: `mold`, `lld`
- **macOS**: `lld`, `zld`

```bash
# Nightly parallel rustc (requires nightly toolchain)
export RUSTUP_TOOLCHAIN=nightly
export PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"

# Fast linker (install one of mold or lld, then select it)
export PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=mold"
# export PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# macOS linker selection
# export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN="-C link-arg=-fuse-ld=lld"
# export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN="-C link-arg=-fuse-ld=zld"

cargo build
```

Opt out of fast linker flags by unsetting `PLATFORM_FAST_LINKER_RUSTFLAGS`/
`PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN`, setting `PLATFORM_LINKER_RUSTFLAGS` (Linux) /
`PLATFORM_LINKER_RUSTFLAGS_DARWIN` (macOS) to an empty string, or exporting
`PLATFORM_DISABLE_FAST_LINKER=1` for scripted runs (the scripts clear fast-linker env vars
when this is set). To override defaults explicitly, set `PLATFORM_LINKER_RUSTFLAGS` (Linux)
or `PLATFORM_LINKER_RUSTFLAGS_DARWIN` (macOS); these override the opt-in fast-linker values
when present.

Fast linker prerequisites (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y mold
# or
sudo apt-get install -y lld
```

### CI Nightly Opt-In

CI runs stable by default. To run nightly builds/tests, trigger the workflow manually and set
`run_nightly=true` in the GitHub Actions workflow dispatch input. The nightly job sets
`PLATFORM_NIGHTLY_RUSTFLAGS` and `PLATFORM_FAST_LINKER_RUSTFLAGS` automatically.

Example for a custom CI step:

```bash
export RUSTUP_TOOLCHAIN=nightly
export PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"
export PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=mold"
cargo test
```

### Test Harness Docker Builds

Dockerfiles are only used for Docker-backed test harnesses. The validator runs directly without Docker in production. Test images accept build args for fast-linker installation and nightly flags:

```bash
docker build \
  --build-arg INSTALL_FAST_LINKER=mold \
  --build-arg PLATFORM_FAST_LINKER_RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
  --build-arg PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0" \
  -t platform:nightly .
```

---

## System Overview

Platform uses a fully decentralized P2P architecture where validators communicate directly via libp2p gossipsub and store data in a distributed hash table (DHT).

Platform involves three main participants:

- **Miners**: Submit code/models to challenges for evaluation
- **Validators**: Run challenge containers, evaluate submissions, and submit weights to Bittensor
- **Sudo Owner**: Configures challenges via signed `SudoAction` messages

The coordination between validators ensures that only verified, consensus-validated results influence the weight distribution on Bittensor.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SUDO OWNER                                     │
│                    (Creates, Updates, Removes Challenges)                   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         P2P NETWORK (libp2p)                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Challenge A │  │ Challenge B │  │ Challenge C │  │     ...     │         │
│  │ (Sandbox)   │  │ (Sandbox)   │  │ (Sandbox)   │  │             │         │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Distributed Hash Table (DHT)                       │  │
│  │           Submissions • Evaluations • Consensus State                 │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
            ▼                     ▼                     ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│   VALIDATOR 1     │ │   VALIDATOR 2     │ │   VALIDATOR N     │
│   (libp2p peer)   │ │   (libp2p peer)   │ │   (libp2p peer)   │
├───────────────────┤ ├───────────────────┤ ├───────────────────┤
│ ┌───────────────┐ │ │ ┌───────────────┐ │ │ ┌───────────────┐ │
│ │ Challenge A   │ │ │ │ Challenge A   │ │ │ │ Challenge A   │ │
│ │ Challenge B   │ │ │ │ Challenge B   │ │ │ │ Challenge B   │ │
│ │ Challenge C   │ │ │ │ Challenge C   │ │ │ │ Challenge C   │ │
│ └───────────────┘ │ │ └───────────────┘ │ │ └───────────────┘ │
│                   │ │                   │ │                   │
│ Evaluates miners  │ │ Evaluates miners  │ │ Evaluates miners  │
│ Shares via P2P    │ │ Shares via P2P    │ │ Shares via P2P    │
└─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   BITTENSOR CHAIN     │
                    │   (Weight Submission) │
                    │  Each Epoch (~72min)  │
                    └───────────────────────┘
```

---

## Miners

### Operations

1. **Development**:

   - Miners develop solutions that solve challenge-specific tasks
   - Solutions are packaged as code submissions with metadata

2. **Submission**:

   - Submit to any validator via the P2P network
   - Submission is distributed via gossipsub and stored in DHT
   - Submission includes: source code, miner hotkey, metadata

3. **Evaluation**:

   - All validators independently evaluate the submission
    - Evaluation runs in isolated sandboxed runtimes (challenge-specific logic)
   - Results are shared via gossipsub and stored in DHT

4. **Weight Distribution**:
   - At epoch end, validators aggregate scores
   - Weights are submitted to Bittensor proportional to miner performance

### Formal Definitions

- **Submission**: $S_i = (code, hotkey_i, metadata)$
- **Submission Hash**: $h_i = \text{SHA256}(S_i)$
- **Evaluation Score**: $s_i^v \in [0, 1]$ - score from validator $v$ for submission $i$

---

## Validators

### Operations

1. **Challenge Synchronization**:

    - Pull challenge artifacts configured by Sudo owner
    - All validators run identical challenge runtimes
   - Health monitoring ensures container availability

2. **Submission Evaluation**:

   - Receive submissions via P2P gossipsub
    - Execute evaluation in sandboxed runtime environment
   - Compute score $s \in [0, 1]$ based on challenge criteria

3. **Result Sharing**:

   - Broadcast `EvaluationResult` via gossipsub to all peers
   - Results stored in distributed hash table (DHT)
   - Validators receive results in real-time via P2P

4. **Score Aggregation**:

   - Collect evaluations from all validators for each submission
   - Compute stake-weighted average to aggregate scores
   - Detect and exclude outlier validators (2σ threshold)

5. **Weight Calculation**:

   - Convert aggregated scores to normalized weights
   - Apply softmax or linear normalization

6. **Weight Submission**:
   - Submit weights to Bittensor per-mechanism at epoch boundaries

### Formal Definitions

- **Evaluation**: $E_i^v = (h_i, s_i^v, t, sig_v)$ where $sig_v$ is validator signature
- **Aggregated Score** (stake-weighted mean, after outlier removal):

$$\bar{s}_i = \frac{\sum_{v \in \mathcal{V}'} S_v \cdot s_i^v}{\sum_{v \in \mathcal{V}'} S_v}$$

Where $\mathcal{V}'$ is the set of validators after outlier removal and $S_v$ is the stake of validator $v$

- **Confidence Score**:

$$c_i = \exp\left( -\frac{\sigma_i}{\tau} \right)$$

Where $\sigma_i$ is standard deviation of scores and $\tau$ is sensitivity scale.

---

## Incentive Mechanism

### Weight Calculation

Platform supports two normalization methods:

#### 1. Softmax Normalization (Default)

Converts scores to probability distribution using temperature-scaled softmax:

$$w_i = \frac{\exp(s_i / T)}{\sum_{j \in \mathcal{M}} \exp(s_j / T)}$$

Where:

- $w_i$ - normalized weight for submission $i$
- $s_i$ - aggregated score for submission $i$
- $T$ - temperature parameter (higher = more distributed)
- $\mathcal{M}$ - set of all evaluated submissions

#### 2. Linear Normalization

Simple proportional distribution:

$$w_i = \frac{s_i}{\sum_{j \in \mathcal{M}} s_j}$$

### Final Weight Conversion

Weights are converted to Bittensor `u16` format:

$$W_i = \lfloor w_i' \times 65535 \rfloor$$

---

## Consensus Mechanism

### PBFT (Practical Byzantine Fault Tolerance)

Platform uses simplified PBFT for validator consensus:

#### Threshold

For $n$ validators with maximum $f$ faulty nodes:

$$\text{threshold} = 2f + 1 = \left\lfloor \frac{2n}{3} \right\rfloor + 1$$

#### Consensus Flow

1. **Propose**: Leader broadcasts `Proposal(action, block_height)`
2. **Vote**: Validators verify and broadcast `Vote(proposal_id, approve/reject)`
3. **Commit**: If $\geq \text{threshold}$ approvals received, apply action

#### Supported Actions

- `SudoAction::AddChallenge` - Add new challenge container
- `SudoAction::UpdateChallenge` - Update challenge configuration
- `SudoAction::RemoveChallenge` - Remove challenge
- `SudoAction::SetRequiredVersion` - Mandatory version update
- `NewBlock` - State checkpoint

---

## Score Aggregation

### Stake-Weighted Aggregation

Each validator's score is weighted by their stake:

$$\bar{s}_i = \frac{\sum_{v \in \mathcal{V}} S_v \cdot s_i^v}{\sum_{v \in \mathcal{V}} S_v}$$

Where $S_v$ is the stake of validator $v$.

### Outlier Detection

Validators with anomalous scores are detected using z-score:

$$z_v = \frac{s_i^v - \mu_i}{\sigma_i}$$

Where $\mu_i$ and $\sigma_i$ are mean and standard deviation of scores for submission $i$.

Validators with $|z_v| > z_{threshold}$ (default 2.0) are excluded from aggregation.

### Confidence Calculation

Agreement among validators determines confidence:

$$\text{confidence}_i = \exp\left( -\frac{\sigma_i}{0.1} \right)$$

Low confidence (high variance) may exclude submission from weights.

---

## Security Considerations

### Stake-Based Security

- **Minimum Stake**: 1000 TAO required for validator participation
- **Sybil Resistance**: Creating fake validators requires significant capital
- **Stake Validation**: All API requests verified against metagraph stakes

### Network Protection

| Protection           | Configuration         |
| -------------------- | --------------------- |
| Rate Limiting        | 100 msg/sec per peer  |
| Connection Limiting  | 5 connections per IP  |
| Blacklist Duration   | 1 hour for violations |
| Failed Attempt Limit | 10 before blacklist   |

### Evaluation Isolation

- **Sandboxed Execution**: Agents run in isolated runtimes
- **Resource Limits**: Memory, CPU, and time constraints
- **Deterministic Execution**: All validators run identical containers

### Data Integrity

- **DHT Storage**: Data distributed across validators via Kademlia DHT
- **Signature Verification**: All messages signed by validator keys
- **Gossipsub Sync**: Validators receive real-time state updates via P2P

---

## Formal Analysis

### Miner Utility Maximization

Miners maximize reward by submitting high-performing solutions:

$$\max_{S_i} \quad w_i = \frac{\exp(\bar{s}_i / T)}{\sum_j \exp(\bar{s}_j / T)}$$

Subject to:

- Submission must pass validation
- Score determined by challenge criteria

### Security Guarantees

1. **Byzantine Tolerance**: System remains correct with up to $f = \lfloor(n-1)/3\rfloor$ faulty validators

2. **Evaluation Fairness**:

   - Deterministic sandboxed execution
   - Outlier detection excludes manipulators
   - Stake weighting resists Sybil attacks

3. **Liveness**: System progresses if $> 2/3$ validators are honest and connected

---

## Epoch Lifecycle

Each Bittensor epoch (~360 blocks, ~72 minutes):

### Continuous Evaluation

**Evaluation runs continuously** throughout the entire epoch. Validators constantly:

- Receive and process submissions from challenges via P2P
- Execute evaluations in sandboxed runtimes
- Broadcast results via gossipsub
- Aggregate scores from all validators

### Weight Submission

At the end of each epoch, validators submit weights to Bittensor based on aggregated scores.

---

## Quick Start

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cp .env.example .env
# Edit .env: add your VALIDATOR_SECRET_KEY (BIP39 mnemonic)
mkdir -p data
cargo build --release --bin validator-node
./target/release/validator-node --data-dir ./data --secret-key "${VALIDATOR_SECRET_KEY}"

# Optional: install Docker + Compose for test harnesses only
./scripts/install-docker.sh
```

## P2P Architecture

Platform uses a fully decentralized architecture where validators communicate via libp2p without requiring a central server.

### Benefits
- **No single point of failure** - No central server dependency
- **Fully trustless** - Validators reach consensus via PBFT
- **Bittensor-linked state** - State changes are linked to Subtensor block numbers
- **DHT storage** - Submissions and evaluations stored across the network

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   VALIDATOR 1   │◄───►│   VALIDATOR 2   │◄───►│   VALIDATOR N   │
│   (libp2p)      │     │   (libp2p)      │     │   (libp2p)      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     BITTENSOR CHAIN     │
                    │     (Weight Commits)    │
                    │   State linked to blocks │
                    └─────────────────────────┘
```

## Hardware Requirements

| Resource    | Minimum    | Recommended |
| ----------- | ---------- | ----------- |
| **CPU**     | 4 vCPU     | 8 vCPU      |
| **RAM**     | 16 GB      | 32 GB       |
| **Storage** | 250 GB SSD | 500 GB NVMe |
| **Network** | 100 Mbps   | 100 Mbps    |

> **Note**: Hardware requirements may increase over time as more challenges are added to the network. Each challenge runs in its own sandboxed runtime and may have specific resource needs. Monitor your validator's resource usage and scale accordingly.

## Network Requirements

| Port      | Protocol  | Usage                                      |
| --------- | --------- | ------------------------------------------ |
| 9000/tcp  | libp2p    | P2P communication (gossipsub, DHT)         |
| 8090/tcp  | WebSocket | Container Broker (challenge communication) |

## Configuration

| Variable               | Description                          | Default                                     | Required     |
| ---------------------- | ------------------------------------ | ------------------------------------------- | ------------ |
| `VALIDATOR_SECRET_KEY` | BIP39 mnemonic or hex key            | -                                           | Yes          |
| `SUBTENSOR_ENDPOINT`   | Bittensor RPC endpoint               | `wss://entrypoint-finney.opentensor.ai:443` | No           |
| `NETUID`               | Subnet UID                           | `100`                                       | No           |
| `RUST_LOG`             | Log level                            | `info`                                      | No           |
| `P2P_LISTEN_ADDR`      | libp2p listen address                | `/ip4/0.0.0.0/tcp/9000`                     | No           |
| `BOOTSTRAP_PEERS`      | Bootstrap peers (comma-separated)    | -                                           | No           |
| `PLATFORM_PUBLIC_URL`  | Public URL for challenge containers  | -                                           | Yes          |
| `BROKER_WS_PORT`       | Container broker WebSocket port      | `8090`                                      | No           |
| `BROKER_JWT_SECRET`    | JWT secret for broker authentication | -                                           | Yes          |

## Binary

The `validator-node` binary runs the validator:

```bash
validator-node
```

Environment variables configure all options (see Configuration table above).

---

## Auto-Update (Critical)

**All validators MUST use auto-update.** Watchtower checks for new images at synchronized times (`:00`, `:05`, `:10`, `:15`...) so all validators update together.

If validators run different versions:

- Consensus fails (state hash mismatch)
- Weight submissions rejected
- Network forks

**Do not disable Watchtower.**

---

## Conclusion

Platform creates a trustless, decentralized framework for evaluating miner submissions on Bittensor. By combining:

- **PBFT Consensus** for Byzantine fault tolerance
- **Stake-Weighted Aggregation** for Sybil resistance
- **Sandboxed Isolation** for deterministic evaluation (challenge-specific logic)
- **P2P Architecture** using libp2p gossipsub and DHT for fully decentralized state

The system ensures that only genuine, high-performing submissions receive rewards, while making manipulation economically infeasible. Validators are incentivized to provide accurate evaluations through reputation mechanics, and miners are incentivized to submit quality solutions through the weight distribution mechanism.

---

## License

MIT