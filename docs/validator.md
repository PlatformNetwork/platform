# Validator Guide

This guide explains how to run a Platform validator node on the Bittensor network.

## Key Features

- **No GPU required** - Validators run on standard CPU servers
- **No third-party APIs** - No OpenAI, Anthropic, or other API keys needed
- **One command setup** - Just run `docker compose up -d`
- **Auto-updates** - Watchtower keeps your validator in sync automatically
- **Minimal maintenance** - Set it and forget it

---

## Quick start for validators

That's all you need to do:

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cp .env.example .env
# Edit .env: add your VALIDATOR_SECRET_KEY (BIP39 mnemonic)

# Optional: install Docker + Compose (used by test scripts)
./scripts/install-docker.sh

# Create the Docker network (required, one-time setup)
docker network create platform-network

# Start the validator
docker compose up -d
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

- Docker 24.0+
- Docker Compose v2
- Linux (Ubuntu 22.04+ recommended)
- `scripts/install-docker.sh` (automated installer used by test scripts)

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

## Docker Compose Configuration

The default `docker-compose.yml`:

```yaml
services:
  validator:
    image: ghcr.io/platformnetwork/validator:latest
    restart: unless-stopped
    ports:
      - "9000:9000"
      - "8545:8545"
    volumes:
      - ./data:/data
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - VALIDATOR_SECRET_KEY=${VALIDATOR_SECRET_KEY}
      - SUBTENSOR_ENDPOINT=${SUBTENSOR_ENDPOINT:-wss://entrypoint-finney.opentensor.ai:443}
      - NETUID=${NETUID:-100}
      - RUST_LOG=${RUST_LOG:-info}

  watchtower:
    image: containrrr/watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --interval 300 --cleanup validator
```

---

## Auto-Update (Critical)

**All validators MUST use Watchtower for auto-updates.**

Watchtower automatically pulls new validator images and restarts the container. This ensures all validators run the same version, which is critical for consensus.

### Why Auto-Update is Required

- **Consensus**: All validators must run identical code
- **State Hash**: Different versions produce different state hashes
- **Network Forks**: Version mismatch causes network splits
- **Weight Rejection**: Outdated validators may have weights rejected

### Watchtower Configuration

The default configuration checks for updates every 5 minutes:

```yaml
watchtower:
  image: containrrr/watchtower
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  command: --interval 300 --cleanup validator
```

**Do not disable Watchtower.**

---

## Monitoring

### Check Validator Status

```bash
# View logs
docker compose logs -f validator

# Check container status
docker compose ps

# View resource usage
docker stats validator
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

Validator deployment tests rely on Docker and Docker Compose. The test harness automatically invokes `scripts/install-docker.sh` when Docker is missing (unless `PLATFORM_TEST_DOCKER_MODE=skip`).

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

### Docker Issues

**Problem**: `Cannot connect to Docker daemon`

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart docker
sudo systemctl restart docker
```

**Problem**: Challenge containers not starting

```bash
# Verify docker.sock is mounted
docker compose exec validator ls -la /var/run/docker.sock

# Check Docker permissions
docker ps
```

### State Divergence

**Problem**: `DB DIVERGENCE detected`

This means your state differs from the majority. Usually resolves automatically:

1. Wait for automatic sync (up to 2 minutes)
2. If persistent, restart the validator:
   ```bash
   docker compose restart validator
   ```
3. If still diverged, reset state:
   ```bash
   docker compose down
   rm -rf ./data/distributed-db
   docker compose up -d
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

Watchtower handles automatic upgrades. For manual upgrades:

```bash
# Pull latest images
docker compose pull

# Restart with new images
docker compose up -d

# Verify version
docker compose logs validator | grep "version"
```

---

## Stopping the Validator

```bash
# Graceful stop
docker compose down

# Stop and remove volumes (warning: deletes data)
docker compose down -v
```

---

## Support

- **GitHub Issues**: [platform/issues](https://github.com/PlatformNetwork/platform/issues)
- **Discord**: Join our community for real-time support
