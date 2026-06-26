# -*- coding: utf-8 -*-
"""
Evaluate a trained policy against the uniform-random baseline.

Loads a Q-table from ``policy.json``, plays the greedy (epsilon=0) trained
agent as Team 1 against ``UniformRandomAgent`` opponents (Team 0) over N seeded
games, and reports the trained win-rate next to the ~50% random-vs-random
baseline. Honest measurement -- no overclaiming: whatever the table yields is
what is printed.

Usage
-----
    python -m src.Training.eval_rl --games 200 --seed 1000
"""

import argparse
import os

from src.Harness.Simulator import (evaluate, format_winrate_table,
                                    default_random_factory)
from src.AgentTypes.RLAgent import TeamTDAgentClass, load_policy

DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.json")


def _make_trained_factory(qtable):
    """Factory producing greedy, non-learning agents that use ``qtable``."""
    def factory(player_id, team_id):
        return TeamTDAgentClass(player_id, team_id, qtable,
                                epsilon=0.0, learn=False)
    return factory


def evaluate_policy(policy_path=DEFAULT_POLICY_PATH, games=200, seed=1000, max_turns=200):
    """Evaluate the trained policy (Team 1) vs random (Team 0).

    Returns the trained-vs-random stats dict and the random-vs-random baseline
    stats dict.
    """
    qtable = load_policy(policy_path)
    trained_factory = _make_trained_factory(qtable)

    trained_stats = evaluate(default_random_factory, trained_factory,
                             games=games, seed=seed, max_turns=max_turns)
    baseline_stats = evaluate(default_random_factory, default_random_factory,
                              games=games, seed=seed, max_turns=max_turns)
    return trained_stats, baseline_stats


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate a trained ARL Battlespace policy.")
    parser.add_argument("--policy-path", default=DEFAULT_POLICY_PATH)
    parser.add_argument("--games", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1000)
    parser.add_argument("--max-turns", type=int, default=200)
    args = parser.parse_args(argv)

    print(f"Evaluating policy {args.policy_path} over {args.games} games "
          f"(seed={args.seed})...\n")
    trained_stats, baseline_stats = evaluate_policy(
        args.policy_path, games=args.games, seed=args.seed, max_turns=args.max_turns)

    print("Trained agent (Team 1, greedy) vs UniformRandomAgent (Team 0):")
    print(format_winrate_table(trained_stats,
                               label_a="Team 0 (Random)", label_b="Team 1 (Trained)"))
    print()
    print("Reference baseline -- UniformRandom vs UniformRandom:")
    print(format_winrate_table(baseline_stats,
                               label_a="Team 0 (Random)", label_b="Team 1 (Random)"))
    print()
    trained_wr = trained_stats["team_b_winrate"]
    baseline_wr = baseline_stats["team_b_winrate"]
    delta = trained_wr - baseline_wr
    print(f"Trained Team 1 win-rate:  {trained_wr:.1%}")
    print(f"Baseline Team 1 win-rate: {baseline_wr:.1%}")
    print(f"Improvement over baseline: {delta:+.1%}")
    return trained_stats, baseline_stats


if __name__ == "__main__":
    main()
