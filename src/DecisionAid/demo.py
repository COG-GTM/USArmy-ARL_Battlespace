# -*- coding: utf-8 -*-
"""
Demonstration of the threat-prioritization + weapon-to-target assignment aid.

Builds a deterministic mid-game contact scenario (an enemy assault on the
defender's flag), runs the real game's limited-visibility ``observe`` to produce
the defender's observed state, then prints:

1. Ranked enemy threats (most dangerous first) with rationale.
2. The recommended weapon-to-target assignment (one-to-one) with Pk per pairing.
3. (If ``policy.json`` exists) the trained RL agent's top COA recommendations,
   showing how WS2 and WS3 compose into a single commander's decision aid.

Run with::

    python -m src.DecisionAid.demo
"""

import os

from src.Games.TeamCaptureFlagGame import TeamCaptureFlagClass
from src.StateTypes.TeamState import TeamStateClass
from src.AgentTypes.TeamAgents import TeamUniformRandomAgentClass
from src.UnitTypes.SoldierModule import SoldierClass
from src.UnitTypes.TankModule import TankClass
from src.UnitTypes.TruckModule import TruckClass
from src.UnitTypes.ExampleUnit import FlagClass
from src.DecisionAid import ThreatModel, Assignment

DEFENDER_ID = 0
ATTACKER_ID = 1
BOARD_SIZE = (10, 11, 2)


def build_contact_scenario():
    """Build a deterministic mid-game state where attackers close on our flag.

    Defender (Team 0, agent 0) holds a flag guarded by two units. Attacker
    (Team 1, agent 1) pushes a Tank, Soldier and Truck into visible range of the
    guards. Returns ``(game, state)``.
    """
    agents = {
        DEFENDER_ID: TeamUniformRandomAgentClass(DEFENDER_ID, 0),
        ATTACKER_ID: TeamUniformRandomAgentClass(ATTACKER_ID, 1),
    }

    state = TeamStateClass()
    state.BoardSize = BOARD_SIZE
    state.FlagPosition = {}

    up = (0, 1, 0)
    down = (0, -1, 0)

    # Defender flag + guards (high VisibleRange so the assault is observed).
    flag_pos = (5, 5, 0)
    state.Units[1] = FlagClass(1, DEFENDER_ID, 1, Position=flag_pos, Orientation=up)
    state.Units[2] = SoldierClass(2, DEFENDER_ID, 1, Position=(5, 4, 0), Orientation=up, VisibleRange=3)
    state.Units[3] = TankClass(3, DEFENDER_ID, 1, Position=(4, 4, 0), Orientation=up, VisibleRange=3)
    state.FlagPosition[DEFENDER_ID] = flag_pos

    # Attacker assault force bearing down on the flag.
    state.Units[11] = TankClass(11, ATTACKER_ID, 1, Position=(5, 7, 0), Orientation=down, VisibleRange=3)
    state.Units[12] = SoldierClass(12, ATTACKER_ID, 1, Position=(6, 6, 0), Orientation=down, VisibleRange=3)
    state.Units[13] = TruckClass(13, ATTACKER_ID, 1, Position=(4, 6, 0), Orientation=down, VisibleRange=3)
    attacker_flag = (5, 10, 0)
    state.Units[14] = FlagClass(14, ATTACKER_ID, 1, Position=attacker_flag, Orientation=down)
    state.FlagPosition[ATTACKER_ID] = attacker_flag

    state.Players = range(2)
    game = TeamCaptureFlagClass(agents)
    return game, state


def print_section(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def run_demo():
    game, state = build_contact_scenario()
    observed_states = game.observe(state)
    defender_obs = observed_states[DEFENDER_ID]

    print_section("ARL Battlespace Decision Aid -- Defender (Team 0) perspective")
    print("Scenario: enemy assault force closing on our flag at "
          f"{state.FlagPosition[DEFENDER_ID]}.")
    visible_enemy = [uid for uid, units in defender_obs.items()
                     if units and next(iter(units)).Owner is None]
    print(f"Visible enemy units this turn (fog of war): {sorted(visible_enemy)}")

    # WS3: threat prioritization.
    threats = ThreatModel.score(defender_obs, state, DEFENDER_ID)
    print_section("1) Ranked enemy threats")
    for rank, t in enumerate(threats, 1):
        print(f"  #{rank}  {t['rationale']}")

    # WS3: weapon-to-target assignment.
    friendly = ThreatModel.friendly_units(defender_obs, DEFENDER_ID)
    assignments = Assignment.optimize(friendly, threats)
    print_section("2) Recommended weapon-to-target assignment")
    if assignments:
        print(f"   (solver: {assignments[0]['solver']})")
    for a in assignments:
        print(f"  {a['rationale']}")

    # WS2 + WS3 integration: RL COA recommendations, if a policy is available.
    policy_path = os.path.join(os.path.dirname(__file__), "..", "Training", "policy.json")
    policy_path = os.path.normpath(policy_path)
    if os.path.exists(policy_path):
        from src.AgentTypes.RLAgent import TeamTDAgentClass, load_policy
        qtable = load_policy(policy_path)
        advisor = TeamTDAgentClass(DEFENDER_ID, 0, qtable, epsilon=0.0, learn=False)
        coas = advisor.recommendActions(defender_obs, state, topk=3)
        print_section("3) RL agent course-of-action (COA) recommendations")
        print(f"   (from trained policy: {policy_path})")
        for unit_id, options in coas.items():
            print(f"  Unit #{unit_id}:")
            for action, q, label in options:
                print(f"      - {label}")
    else:
        print_section("3) RL agent COA recommendations")
        print("   (skipped -- no policy.json found; run src.Training.train_rl first)")

    print()
    return threats, assignments


if __name__ == "__main__":
    run_demo()
