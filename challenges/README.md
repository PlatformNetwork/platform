# Platform Challenge Crates

This directory contains challenge crates that can be integrated with the Platform validator network.

## Directory Structure

```
challenges/
├── README.md           # This file
├── example-challenge/  # Example challenge template (future)
└── [your-challenge]/   # Your custom challenge crate
```

## Adding a New Challenge Crate

1. Create your challenge crate in this directory or reference it as a git dependency
2. Implement the `Challenge` trait from `platform-challenge-sdk`
3. Register your challenge in the challenge registry
4. Update the workspace `Cargo.toml` if adding locally

## External Challenge Crates

Challenge crates can also be external (like term-challenge). They should:
- Import `platform-challenge-sdk` as a dependency
- Implement the `ServerChallenge` trait
- Provide Docker configuration for evaluation

## Challenge Crate Requirements

- Must implement `platform-challenge-sdk::ServerChallenge`
- Must provide `/evaluate` HTTP endpoint
- Must handle graceful shutdown signals
- Must support state persistence for hot-reload

## Example

See [term-challenge](https://github.com/PlatformNetwork/term-challenge) for a complete example.

## Documentation

For detailed integration instructions, see the [Challenge Integration Guide](../docs/challenge-integration.md).
