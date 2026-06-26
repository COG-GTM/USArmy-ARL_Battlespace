# -*- coding: utf-8 -*-
"""
Headless, deterministic AI-vs-AI simulation harness for ARL Battlespace.

This module runs Capture-the-Flag matches between two teams of agents without
any Tk UI or network sockets. The start-state construction (3 ground units + 1
air unit + 1 flag per player, plus the central wall/minefield with a gap) mirrors
the placement logic in ``test/ServerWithUI.py`` so trained agents and decision
aids see the same battlespace the human-vs-AI server produces.

Public API
----------
- ``build_start_state(agentFactoryA, agentFactoryB, seed)`` -> (Game, State0)
- ``run_match(agentFactoryA, agentFactoryB, seed, max_turns)`` -> winning TeamID
- ``evaluate(agentFactoryA, agentFactoryB, games, seed, max_turns)`` -> stats dict

CLI
---
``python -m src.Harness.Simulator --games 200 --seed 0`` runs a baseline
RandomAgent-vs-RandomAgent evaluation and prints a win-rate table.
"""

import argparse
import contextlib
import io
import math
import os
import random
from copy import deepcopy

from src.StateTypes.TeamState import TeamStateClass
from src.Games.TeamCaptureFlagGame import TeamCaptureFlagClass
from src.AgentTypes.TeamAgents import TeamUniformRandomAgentClass
from src.UnitTypes.SoldierModule import SoldierClass
from src.UnitTypes.TankModule import TankClass
from src.UnitTypes.TruckModule import TruckClass
from src.UnitTypes.AirplaneModule import AirplaneClass
from src.UnitTypes.ExampleUnit import FlagClass
from src.UnitTypes.WallUnitModule import WallClass

# --- Battlespace configuration (matches test/ServerWithUI.py) -----------------
BOARD_SIZE = (10, 11, 2)
HEALTH = 1
# Players 0 and 1 form Team 0; players 2 and 3 form Team 1.
TEAM_A_PLAYERS = (0, 1)
TEAM_B_PLAYERS = (2, 3)
TEAM_A_ID = 0
TEAM_B_ID = 1
# The wall/minefield is owned by a dedicated non-playing agent on its own team.
WALL_OWNER_ID = 4
WALL_TEAM_ID = 2
UNITS_PER_PLAYER = 5
GAP_LOCATION = (4, 5, 0)
DEFAULT_MAX_TURNS = 200


def _two_player_regions(board_size):
    """Return ``(UnitsCord, FlagCord)`` placement regions per player.

    Replicates ``TwoPlayerCord`` and ``TwoPlayerCordFlag`` from
    ``test/ServerWithUI.py`` for the four players (0..3).
    """
    bx, by, bz = board_size
    units_cord = (
        ((0, math.floor(bx / 2 - 1)), (0, math.floor(by / 2 - 1)), (0, bz - 1)),
        ((math.ceil(bx / 2), bx - 1), (0, math.floor(by / 2) - 1), (0, bz - 1)),
        ((0, math.floor(bx / 2 - 1)), (math.ceil(by / 2), by - 1), (0, bz - 1)),
        ((math.ceil(bx / 2), bx - 1), (math.ceil(by / 2), by - 1), (0, bz - 1)),
    )
    flag_cord = (
        ((0, math.floor(bx / 2) - 1), (0, math.floor(by / 2) - 4), (0, bz - 1)),
        ((math.ceil(bx / 2), bx - 1), (0, math.floor(by / 2) - 4), (0, bz - 1)),
        ((0, math.floor(bx / 2) - 1), (math.floor(by / 2), by - 1), (0, bz - 1)),
        ((math.ceil(bx / 2), bx - 1), (math.ceil(by / 2), by - 1), (0, bz - 1)),
    )
    return units_cord, flag_cord


def _place_player_units(state, player_id, units_cord, flag_cord):
    """Randomly place one player's 5 units, mirroring ``placeRandomUnits``."""
    while True:
        soldier_pos = (random.randint(units_cord[player_id][0][0], units_cord[player_id][0][1]),
                       random.randint(units_cord[player_id][1][0], units_cord[player_id][1][1]), 0)
        truck_pos = (random.randint(units_cord[player_id][0][0], units_cord[player_id][0][1]),
                     random.randint(units_cord[player_id][1][0], units_cord[player_id][1][1]), 0)
        tank_pos = (random.randint(units_cord[player_id][0][0], units_cord[player_id][0][1]),
                    random.randint(units_cord[player_id][1][0], units_cord[player_id][1][1]), 0)
        if soldier_pos != truck_pos and soldier_pos != tank_pos and truck_pos != tank_pos:
            break
    airplane_pos = (random.randint(units_cord[player_id][0][0], units_cord[player_id][0][1]),
                    random.randint(units_cord[player_id][1][0], units_cord[player_id][1][1]), 1)
    flag_pos = (random.randint(flag_cord[player_id][0][0], flag_cord[player_id][0][1]),
                random.randint(flag_cord[player_id][1][0], flag_cord[player_id][1][1]), 0)

    base = player_id * UNITS_PER_PLAYER
    orientation = (0, 1, 0)
    state.Units[base + 0] = SoldierClass(base + 0, player_id, HEALTH, Position=soldier_pos, Orientation=orientation)
    state.Units[base + 1] = TruckClass(base + 1, player_id, HEALTH, Position=truck_pos, Orientation=orientation)
    state.Units[base + 2] = TankClass(base + 2, player_id, HEALTH, Position=tank_pos, Orientation=orientation)
    state.Units[base + 3] = AirplaneClass(base + 3, player_id, HEALTH, Position=airplane_pos, Orientation=orientation)
    state.Units[base + 4] = FlagClass(base + 4, player_id, HEALTH, Position=flag_pos, Orientation=orientation)
    state.FlagPosition[player_id] = flag_pos


def _place_walls(state):
    """Place the central wall/minefield row with a single gap."""
    num_units = UNITS_PER_PLAYER * (len(TEAM_A_PLAYERS) + len(TEAM_B_PLAYERS))
    for boulder in range(BOARD_SIZE[0]):
        if boulder != GAP_LOCATION[0]:
            uid = num_units + boulder
            state.Units[uid] = WallClass(uid, WALL_OWNER_ID, 1,
                                         Position=(boulder, GAP_LOCATION[1], GAP_LOCATION[2]),
                                         Orientation=(0, 1, 0))


class _CappedTeamCaptureFlagClass(TeamCaptureFlagClass):
    """Capture-the-Flag game with a maximum-turn cap to guarantee termination.

    Random-vs-random play can otherwise run indefinitely if neither team
    engages. Reaching the cap is treated as a draw by callers.
    """

    def __init__(self, agents, max_turns=DEFAULT_MAX_TURNS):
        TeamCaptureFlagClass.__init__(self, agents)
        self._max_turns = max_turns
        self._turns = 0

    def continueGame(self, State):
        self._turns += 1
        if self._turns >= self._max_turns:
            return False
        return TeamCaptureFlagClass.continueGame(self, State)


def default_random_factory(player_id, team_id):
    """Factory producing the baseline uniform-random team agent."""
    return TeamUniformRandomAgentClass(player_id, team_id)


def build_start_state(agentFactoryA=default_random_factory,
                      agentFactoryB=default_random_factory,
                      seed=None, max_turns=DEFAULT_MAX_TURNS):
    """Construct a fresh game and its initial state.

    Parameters
    ----------
    agentFactoryA, agentFactoryB : callable(player_id, team_id) -> AgentClass
        Factories building the agents controlling Team 0 and Team 1 respectively.
    seed : int or None
        Seed for the global RNG, controlling unit placement (and, downstream,
        any agent that samples from ``random``). Pass an int for reproducibility.
    max_turns : int
        Maximum number of turns before the match is declared a draw.

    Returns
    -------
    (game, state0) : (_CappedTeamCaptureFlagClass, TeamStateClass)
    """
    if seed is not None:
        random.seed(seed)

    state0 = TeamStateClass()
    state0.BoardSize = BOARD_SIZE
    state0.FlagPosition = {}
    units_cord, flag_cord = _two_player_regions(BOARD_SIZE)

    agents = {}
    for pid in TEAM_A_PLAYERS:
        agents[pid] = agentFactoryA(pid, TEAM_A_ID)
        _place_player_units(state0, pid, units_cord, flag_cord)
    for pid in TEAM_B_PLAYERS:
        agents[pid] = agentFactoryB(pid, TEAM_B_ID)
        _place_player_units(state0, pid, units_cord, flag_cord)

    # The wall owner is a non-playing agent so that ownership/team lookups in
    # the game rules resolve for wall units.
    agents[WALL_OWNER_ID] = TeamUniformRandomAgentClass(WALL_OWNER_ID, WALL_TEAM_ID)
    _place_walls(state0)

    state0.Players = range(len(agents))
    game = _CappedTeamCaptureFlagClass(agents, max_turns=max_turns)
    return game, state0


def run_match(agentFactoryA=default_random_factory,
              agentFactoryB=default_random_factory,
              seed=0, max_turns=DEFAULT_MAX_TURNS, verbose=False, return_game=False):
    """Play one match and return the winning TeamID (0 or 1), or ``None`` for a draw.

    A draw occurs on mutual destruction or when the turn cap is reached with both
    teams still holding a flag-capturing unit.
    """
    game, state0 = build_start_state(agentFactoryA, agentFactoryB, seed, max_turns)
    game.PrintOn = verbose
    if verbose:
        result = game.play(state0)
    else:
        with contextlib.redirect_stdout(io.StringIO()):
            result = game.play(state0)
    teams_left = result[2]
    winner = teams_left[0] if len(teams_left) == 1 else None
    if return_game:
        return winner, game, result
    return winner


def evaluate(agentFactoryA=default_random_factory,
             agentFactoryB=default_random_factory,
             games=200, seed=0, max_turns=DEFAULT_MAX_TURNS):
    """Run ``games`` seeded matches and return aggregate outcome statistics.

    Each match ``i`` uses seed ``seed + i`` so the whole evaluation is
    reproducible. Returns a dict with raw counts and rates for Team 0, Team 1,
    and draws.
    """
    wins = {TEAM_A_ID: 0, TEAM_B_ID: 0}
    draws = 0
    for i in range(games):
        winner = run_match(agentFactoryA, agentFactoryB, seed=seed + i, max_turns=max_turns)
        if winner is None:
            draws += 1
        else:
            wins[winner] += 1
    total = max(games, 1)
    return {
        "games": games,
        "team_a_wins": wins[TEAM_A_ID],
        "team_b_wins": wins[TEAM_B_ID],
        "draws": draws,
        "team_a_winrate": wins[TEAM_A_ID] / total,
        "team_b_winrate": wins[TEAM_B_ID] / total,
        "draw_rate": draws / total,
    }


def format_winrate_table(stats, label_a="Team 0 (A)", label_b="Team 1 (B)"):
    """Render an evaluation stats dict as a human-readable table."""
    lines = [
        "+-------------------------+---------+----------+",
        "| Outcome                 |   Count |     Rate |",
        "+-------------------------+---------+----------+",
        f"| {label_a:<23} | {stats['team_a_wins']:>7} | {stats['team_a_winrate']:>7.1%} |",
        f"| {label_b:<23} | {stats['team_b_wins']:>7} | {stats['team_b_winrate']:>7.1%} |",
        f"| {'Draws':<23} | {stats['draws']:>7} | {stats['draw_rate']:>7.1%} |",
        "+-------------------------+---------+----------+",
        f"  Total games: {stats['games']}",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Headless ARL Battlespace AI-vs-AI simulation harness.")
    parser.add_argument("--games", type=int, default=200,
                        help="Number of matches to simulate (default: 200).")
    parser.add_argument("--seed", type=int, default=0,
                        help="Base RNG seed; match i uses seed+i (default: 0).")
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS,
                        help="Turn cap before a match is declared a draw.")
    args = parser.parse_args(argv)

    print(f"Running {args.games} RandomAgent-vs-RandomAgent matches "
          f"(base seed={args.seed}, max_turns={args.max_turns})...")
    stats = evaluate(games=args.games, seed=args.seed, max_turns=args.max_turns)
    print()
    print("Baseline: UniformRandomAgent vs UniformRandomAgent")
    print(format_winrate_table(stats))
    return stats


if __name__ == "__main__":
    main()
