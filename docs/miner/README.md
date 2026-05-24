# Miner Guide

## Purpose

Platform is the routing and coordination layer for multiple challenge subnets. As a miner, you do
not build against Platform-specific scoring logic. You choose a challenge, follow that challenge's
submission contract, and use Platform to reach the challenge's public surface.

## Miner Flow

1. Choose the challenge you want to compete in.
2. Read the challenge repository and miner guide.
3. Build the required submission artifact for that challenge.
4. Submit through the challenge's public route as exposed by Platform.
5. Track challenge-specific status, reports, and leaderboards.
6. Improve your submission based on challenge feedback.
7. Earn rewards when the challenge exports a raw weight for your hotkey and Platform normalizes it
   into final subnet weights.

## How Platform Routes Miner Traffic

Each challenge has a slug, such as `agent-challenge`, `data-fabrication`, `bounty-challenge`, or
`prism`. Platform uses that slug to proxy public challenge requests to the correct isolated
challenge container.

Challenge-specific examples:

```http
POST /challenges/{challenge_slug}/...
GET /challenges/{challenge_slug}/...
```

The exact path after the challenge slug belongs to the challenge repository. Platform does not define
the artifact format, task rules, scoring rubric, or leaderboard fields for each challenge.


## Agent Challenge Frontend API

Frontend reads for Agent Challenge should use the Platform master/proxy base:

```http
GET /v1/registry
GET /challenges/agent-challenge/benchmarks
GET /challenges/agent-challenge/submissions/{id}/status
GET /challenges/agent-challenge/submissions/{id}/events
GET /challenges/agent-challenge/leaderboard
```

Uploads have two public paths:

```http
POST /v1/challenges/agent-challenge/submissions
POST /challenges/agent-challenge/submissions
```

Use `POST /v1/challenges/agent-challenge/submissions` for raw ZIP bridge uploads. Platform verifies the miner upload and forwards it to Agent Challenge. Use `POST /challenges/agent-challenge/submissions` for the JSON base64 generic proxy path when the client signs the challenge-local `/submissions` request.

For v1 lists, `/challenges/agent-challenge/submissions` returns the latest 100 submissions newest-first. `/challenges/agent-challenge/leaderboard` returns one best scoring row per hotkey. Pagination, filtering, and client-selected sorting are deferred to future v2.

The public proxy blocks `/internal/*`, `/health`, and `/version`.

## What Platform Does For Miners

Platform provides:

- one public entry point for multiple challenges;
- challenge routing by slug;
- central challenge discovery;
- final normalization across challenge emissions;
- Bittensor hotkey-to-UID mapping;
- final on-chain weight submission.

## What Challenge Repositories Define

Each challenge defines:

- accepted submission format;
- authentication and signature rules;
- task or project requirements;
- scoring algorithm;
- evaluation limits;
- leaderboard output;
- public status and result endpoints.

## Rewards

Challenge scores are not submitted directly to Bittensor. The flow is:

1. The challenge evaluates miner work.
2. The challenge exports raw hotkey weights.
3. Platform applies the challenge emission share.
4. Platform normalizes across active challenge outputs.
5. Platform maps hotkeys to Bittensor UIDs.
6. Validators submit final weights on-chain.

This means a strong score in one challenge contributes according to that challenge's configured
emission share.

## Miner Checklist

Before submitting:

- Confirm the challenge slug and repository.
- Read the challenge miner guide.
- Use the challenge's required artifact format.
- Sign requests if the challenge requires hotkey signatures.
- Monitor the challenge leaderboard, not only the Platform layer.
- Keep your hotkey consistent across submissions.
- Do not assume two challenges share the same scoring rules.

## Where To Find Challenge Rules

Use the specific challenge repository for detailed mining instructions:

- Agent Challenge: software engineering agents and benchmark tasks.
- Data Fabrication: agentic coding conversation dataset generation.
- Bounty Challenge: owner-created project bounties.
- PRISM: neural architecture search and training variants.
