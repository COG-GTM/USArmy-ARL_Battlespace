# -*- coding: utf-8 -*-
"""
Headless self-play training loop for the tabular Q-learning agent.

Trains a single ``TeamTDAgentClass`` policy via self-play through the headless
harness, decays epsilon over episodes, and PERSISTS the learned Q-table to
``policy.json`` -- fixing the no-save bug in the ``test/ServerWithUI.py`` stub,
which never wrote the table back out.

Usage
-----
    python -m src.Training.train_rl --episodes 500 --seed 0
    python -m src.Training.train_rl --episodes 500 --opponent random

``--opponent self`` (default) learns one shared policy controlling both teams.
``--opponent random`` trains the policy (Team 1) against uniform-random
opponents (Team 0), which directly optimises the evaluation metric.
"""

import argparse
import os
import time

from src.Harness.Simulator import (run_match, TEAM_A_ID, TEAM_B_ID,
                                    BOARD_SIZE, default_random_factory)
from src.AgentTypes.RLAgent import (TeamTDAgentClass, build_qtable, save_policy,
                                    WIN_REWARD, LOSS_REWARD, DRAW_REWARD)

DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.json")


def _make_rl_factory(qtable, epsilon_box, alpha, gamma):
    """Factory producing learning RL agents sharing ``qtable``.

    ``epsilon_box`` is a single-element list so the current epsilon is read at
    agent-construction time (it decays across episodes).
    """
    def factory(player_id, team_id):
        return TeamTDAgentClass(player_id, team_id, qtable,
                                epsilon=epsilon_box[0], alpha=alpha, gamma=gamma, learn=True)
    return factory


def train(episodes=500, seed=0, alpha=0.1, gamma=0.95,
          epsilon_start=0.4, epsilon_end=0.05, opponent="self",
          max_turns=200, policy_path=DEFAULT_POLICY_PATH, verbose=True):
    """Run the self-play training loop and persist the learned policy.

    Returns
    -------
    (qtable, history) : (dict, list[dict])
        The trained Q-table and a per-checkpoint history of win counts.
    """
    qtable = build_qtable(BOARD_SIZE)
    epsilon_box = [epsilon_start]
    rl_factory = _make_rl_factory(qtable, epsilon_box, alpha, gamma)
    random_factory = default_random_factory

    if opponent == "self":
        factory_a, factory_b = rl_factory, rl_factory
    elif opponent == "random":
        factory_a, factory_b = random_factory, rl_factory
    else:
        raise ValueError(f"Unknown opponent mode: {opponent!r}")

    history = []
    window = {TEAM_A_ID: 0, TEAM_B_ID: 0, "draws": 0}
    checkpoint = max(1, episodes // 10)
    start = time.time()

    for ep in range(episodes):
        # Linear epsilon decay.
        frac = ep / max(1, episodes - 1)
        epsilon_box[0] = epsilon_start + (epsilon_end - epsilon_start) * frac

        winner, game, _ = run_match(factory_a, factory_b, seed=seed + ep,
                                    max_turns=max_turns, return_game=True)

        # Apply terminal reward to every learning agent in the played game.
        for agent in game.Agents.values():
            if isinstance(agent, TeamTDAgentClass):
                if winner is None:
                    reward = DRAW_REWARD
                elif agent.TeamID == winner:
                    reward = WIN_REWARD
                else:
                    reward = LOSS_REWARD
                agent.finalizeEpisode(reward)

        if winner is None:
            window["draws"] += 1
        else:
            window[winner] += 1

        if verbose and (ep + 1) % checkpoint == 0:
            elapsed = time.time() - start
            played = ep + 1
            history.append({"episode": played, "epsilon": round(epsilon_box[0], 3),
                            **{str(k): v for k, v in window.items()}})
            print(f"[ep {played:>5}/{episodes}] eps={epsilon_box[0]:.3f} "
                  f"last{checkpoint}: TeamB={window[TEAM_B_ID]} TeamA={window[TEAM_A_ID]} "
                  f"draws={window['draws']} ({elapsed:.0f}s)")
            window = {TEAM_A_ID: 0, TEAM_B_ID: 0, "draws": 0}

    save_policy(qtable, policy_path)
    if verbose:
        print(f"\nSaved learned policy to {policy_path} "
              f"({sum(len(v) for v in qtable.values())} position cells).")
    return qtable, history


def main(argv=None):
    parser = argparse.ArgumentParser(description="Self-play RL training for ARL Battlespace.")
    parser.add_argument("--episodes", type=int, default=500)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--alpha", type=float, default=0.1)
    parser.add_argument("--gamma", type=float, default=0.95)
    parser.add_argument("--epsilon-start", type=float, default=0.4)
    parser.add_argument("--epsilon-end", type=float, default=0.05)
    parser.add_argument("--opponent", choices=["self", "random"], default="self")
    parser.add_argument("--max-turns", type=int, default=200)
    parser.add_argument("--policy-path", default=DEFAULT_POLICY_PATH)
    args = parser.parse_args(argv)

    print(f"Training {args.episodes} episodes (opponent={args.opponent}, seed={args.seed})...")
    train(episodes=args.episodes, seed=args.seed, alpha=args.alpha, gamma=args.gamma,
          epsilon_start=args.epsilon_start, epsilon_end=args.epsilon_end,
          opponent=args.opponent, max_turns=args.max_turns, policy_path=args.policy_path)


if __name__ == "__main__":
    main()
