"""Per-challenge validator-execution adapters (architecture sec 4, G2).

Each adapter maps a pulled assignment onto the matching sibling challenge
package's decentralized validator cycle, run on the validator's OWN broker. The
sibling packages are imported LAZILY (only when an assignment for that challenge
is dispatched) so platform never hard-depends on them.
"""

from __future__ import annotations

from base.validator.agent.adapters.agent_challenge import AgentChallengeCycleExecutor
from base.validator.agent.adapters.prism import PrismCycleExecutor

__all__ = [
    "AgentChallengeCycleExecutor",
    "PrismCycleExecutor",
]
