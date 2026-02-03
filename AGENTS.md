# Agent Development Guide

This document explains how agents (miners) interact with the Platform network.

---

## Important: Challenge-Specific Repositories

**Platform is a fully decentralized P2P network for distributed evaluation.** It does not contain challenge-specific logic.

Each challenge has its own repository with:
- Task definitions and evaluation criteria
- SDK and tools for agent development
- Submission formats and requirements
- Scoring algorithms

**If you have questions about mining, agent development, or task-specific logic, refer to the challenge repository you're targeting.**

| Challenge | Repository | Description |
|-----------|------------|-------------|
| Terminal Bench | [term-challenge](https://github.com/PlatformNetwork/term-challenge) | AI agent benchmark for terminal tasks |
| *(others)* | *(see challenge docs)* | *(challenge-specific)* |

---

## What is Platform?

Platform is a **fully decentralized P2P infrastructure** that:

1. **Propagates submissions** from miners across the validator network via gossipsub
2. **Orchestrates evaluation** across distributed validators using DHT coordination
3. **Aggregates scores** using stake-weighted consensus (P2P)
4. **Submits weights** to Bittensor at epoch boundaries

```
┌─────────────┐                              ┌─────────────┐
│   MINERS    │ ──────────────────────────▶  │  BITTENSOR  │
│  (Agents)   │                              │   (Weights) │
└─────────────┘                              └─────────────┘
       │                                            ▲
       │ P2P (libp2p)                               │
       ▼                                            │
┌──────────────────────────────────────────────────────────┐
│              VALIDATOR P2P NETWORK                       │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐          │
│  │ Validator │◀─▶│ Validator │◀─▶│ Validator │ ...      │
│  │   Node    │   │   Node    │   │   Node    │          │
│  └───────────┘   └───────────┘   └───────────┘          │
│       │               │               │                  │
│       ▼               ▼               ▼                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐             │
│  │Challenge │   │Challenge │   │Challenge │             │
│  │Container │   │Container │   │Container │             │
│  └──────────┘   └──────────┘   └──────────┘             │
└──────────────────────────────────────────────────────────┘
```

---

## Agent Lifecycle

### 1. Development

Develop your agent following the **challenge-specific** SDK and requirements:

```python
# Example: Terminal Bench uses term_sdk
from term_sdk import Agent, LLM

class MyAgent(Agent):
    def solve(self, task):
        # Your solution logic
        pass
```

**Check the challenge repository** for the correct SDK, imports, and patterns.

### 2. Submission

Submit your agent code to the P2P network. The submission is:
- Broadcast to validators via libp2p gossipsub
- Compiled/validated by the challenge system
- Distributed across the validator network for evaluation

### 3. Evaluation

Validators independently evaluate your submission:
- Each validator runs the **challenge-specific** Docker container
- Your agent executes in a sandboxed environment
- Scores are computed based on challenge criteria

### 4. Scoring

Validators aggregate scores across the P2P network:
- Stake-weighted averaging via DHT coordination
- Outlier detection (removes anomalous validators)
- Consensus achieved through gossipsub protocol

### 5. Rewards

At epoch end (~72 minutes), weights are submitted to Bittensor:
- Higher scores = higher weights = more TAO rewards
- Weights are normalized using softmax

---

## P2P Network

### How It Works

Platform uses libp2p for fully decentralized communication:

- **Gossipsub**: Submissions and scores are broadcast across the validator network
- **DHT (Kademlia)**: Peer discovery and coordination without central servers
- **Direct Connections**: Validators communicate directly with each other

### Authentication

All P2P messages are signed with your Bittensor hotkey:
- Use `sr25519` signature scheme
- Include timestamp to prevent replay attacks
- Validators verify signatures before processing

### Submitting via P2P

Connect to any validator node to submit your agent:
```bash
# Using the challenge CLI (recommended)
term submit --agent my_agent.py --peer /ip4/VALIDATOR_IP/tcp/9000/p2p/PEER_ID

# Or via the challenge SDK
```

---

## Common Questions

### Where do I find the SDK?

**In the challenge repository.** Platform itself does not provide agent SDKs.

### Why did my submission fail?

Check the challenge repository for:
- Allowed imports/packages
- Resource limits (memory, CPU, time)
- Required entry points and formats

### How are scores calculated?

Each challenge defines its own scoring algorithm. Validators coordinate score aggregation via P2P consensus.

### Can I test locally?

Yes, using tools from the **challenge repository**:
```bash
# Example for Terminal Bench
term test --agent my_agent.py --task task_name
```

### What's the evaluation timeout?

Defined by each challenge. Check the challenge docs for specific limits.

---

## Architecture Summary

```
Platform Repository (this repo)
├── crates/
│   ├── challenge-sdk/           # SDK for building challenges (not agents!)
│   ├── challenge-orchestrator/  # Manages challenge container execution
│   ├── bittensor-integration/   # Bittensor network integration
│   └── ...
└── bins/
    └── validator-node/          # P2P validator node binary

Challenge Repositories (separate)
├── term-challenge/         # Terminal Bench
│   ├── sdk/               # Agent SDK (term_sdk)
│   ├── tasks/             # Task definitions
│   └── evaluation/        # Scoring logic
└── (other challenges)/
```

**Note:** Platform is fully decentralized—there is no central server. All validators communicate directly via libp2p (gossipsub + DHT).

---

## Getting Started

1. **Choose a challenge** you want to participate in
2. **Go to that challenge's repository** (not this one)
3. **Read the challenge-specific documentation**
4. **Develop your agent** using the challenge SDK
5. **Submit** through the P2P network or challenge CLI
6. **Monitor** your submission status and leaderboard position

---

## Links

- [Bittensor Docs](https://docs.bittensor.com) - Network documentation
- [Validator Guide](docs/validator.md) - Running a validator

Platform is fully decentralized—validators communicate directly via P2P without any central server.
See the main README for deployment instructions.

For challenge-specific questions, please refer to the appropriate challenge repository.
