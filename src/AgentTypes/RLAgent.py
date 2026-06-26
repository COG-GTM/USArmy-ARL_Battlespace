# -*- coding: utf-8 -*-
"""
Tabular temporal-difference (Q-learning) agent for ARL Battlespace.

``TeamTDAgentClass`` is the working implementation of the "RL coming soon"
stub referenced in ``test/ServerWithUI.py``. It reuses that stub's intended
Q-table schema::

    QTable[domain][positionKey][orientationKey][action] -> value

where ``domain`` is ``"land"`` or ``"air"``, ``positionKey`` is ``"x, y"``,
``orientationKey`` is ``"ox, oy"`` and ``action`` is an action name. Because the
schema matches the stub, a table trained here is compatible with the existing
nested-dict format and is what ``src/Training/train_rl.py`` persists to
``policy.json``.

The agent provides:
- ``chooseActions`` : epsilon-greedy action selection over each unit's legal
  actions using Q-values (advisory or self-play).
- ``updateDecisionModel`` : per-turn TD(0) update with reward shaping derived
  from the stub's ``land_acts``/``air_acts`` seed values plus kill/loss signals.
- ``finalizeEpisode`` : Monte-Carlo backup of the terminal win/loss reward
  through the episode trajectory.
- ``recommendActions`` : ranked courses of action (COAs) per controlled unit for
  a human commander, instead of silently auto-acting.
"""

import itertools
import json
from random import random, choice

from src.AgentModule import AgentClass
from src.UnitTypes.AirplaneModule import AirplaneClass
from src.UnitTypes.AirUnitModule import AirUnitClass
from src.UnitTypes.ExampleUnit import FlagClass


def nth(iterable, n, default=None):
    "Returns the nth item or a default value"
    return next(itertools.islice(iterable, n, None), default)


# Reward-shaping seed values, copied verbatim from the QTable seed in
# test/ServerWithUI.py (land_acts/air_acts). Used both to initialise Q-values
# and as a per-turn shaping reward that biases units toward useful actions.
LAND_ACTS = {
    'doNothing': -0.1, 'turn-135': 0, 'turn-90': 0, 'turn-45': 0, 'turn0': 0,
    'turn45': 0, 'turn90': 0, 'turn135': 0, 'turn180': 0, 'advance1': 0.0,
    'shoot': 0, 'ram': 0.0,
}
AIR_ACTS = {
    'doNothing': 0, 'turn-135': 0, 'turn-90': 0, 'turn-45': 0, 'turn0': 0,
    'turn45': 0, 'turn90': 0, 'turn135': 0, 'turn180': 0,
    'advance0,-2': 0.9 / 12, 'advance-1,-1': 0.9 / 12, 'advance0,-1': 0.9 / 12,
    'advance1,-1': 0.9 / 12, 'advance-2,0': 0.9 / 12, 'advance-1,0': 0.9 / 12,
    'advance0,0': 0, 'advance1,0': 0.9 / 12, 'advance2,0': 0.9 / 12,
    'advance-1,1': 0.9 / 12, 'advance0,1': 0.9 / 12, 'advance1,1': 0.9 / 12,
    'advance0,2': 0.9 / 12, 'ascend': 0, 'descend': 0, 'shoot': 0.05, 'bomb': 0.05,
}

ORIENTATIONS = ["0, 1", "0, -1", "1, 0", "-1, 0", "1, 1", "1, -1", "-1, 1", "-1, -1"]

# Terminal episode rewards (applied by finalizeEpisode).
WIN_REWARD = 1.0
LOSS_REWARD = -1.0
DRAW_REWARD = -0.1
# Per-turn shaping rewards.
ENEMY_KILL_REWARD = 0.5
FRIENDLY_LOSS_PENALTY = 0.5


def build_qtable(board_size):
    """Build a fresh Q-table seeded with the land/air shaping values.

    Mirrors the nested-dict construction in ``test/ServerWithUI.py`` so the
    persisted artifact is schema-compatible.
    """
    qtable = {"land": {}, "air": {}}
    for x in range(board_size[0]):
        for y in range(board_size[1]):
            key = f"{x}, {y}"
            qtable["land"][key] = {o: LAND_ACTS.copy() for o in ORIENTATIONS}
            qtable["air"][key] = {o: AIR_ACTS.copy() for o in ORIENTATIONS}
    return qtable


def position_key(position):
    return f"{int(position[0])}, {int(position[1])}"


def orientation_key(orientation):
    if orientation is None:
        return ORIENTATIONS[0]
    return f"{int(orientation[0])}, {int(orientation[1])}"


def domain_of(unit):
    """Return the Q-table domain (``"air"``/``"land"``) for ``unit``."""
    if isinstance(unit, (AirplaneClass, AirUnitClass)):
        return "air"
    return "land"


class TeamTDAgentClass(AgentClass):
    """Team-aware tabular Q-learning agent.

    Parameters
    ----------
    ID : int
        Unique agent identifier (must match the key in the game's agent dict).
    TeamID : int
        Identifier of the team this agent belongs to.
    QTable : dict
        Nested Q-table (see module docstring). Shared by reference across the
        agents that learn together; ``__deepcopy__`` deliberately preserves the
        shared reference so updates survive the game engine's ``deepcopy`` of
        agents.
    epsilon : float
        Exploration rate for epsilon-greedy action selection.
    alpha : float
        Learning rate for TD/MC updates.
    gamma : float
        Discount factor.
    learn : bool
        When True, the agent records trajectory and applies updates. Set False
        for pure evaluation/advisory use.
    """

    def __init__(self, ID, TeamID, QTable, epsilon=0.3, alpha=0.1, gamma=0.95, learn=True):
        AgentClass.__init__(self, ID)
        self.TeamID = TeamID
        self.QTable = QTable
        self.epsilon = epsilon
        self.alpha = alpha
        self.gamma = gamma
        self.learn = learn
        self.Went = 0
        # Trajectory of (domain, posKey, orientKey, action) chosen this episode.
        self._trajectory = []

    def __deepcopy__(self, memo):
        # Preserve the shared Q-table reference so that learning performed by the
        # agent copy living inside the game engine accumulates into the master
        # table held by the caller/training loop.
        Duplicate = TeamTDAgentClass(self.ID, self.TeamID, self.QTable,
                                     epsilon=self.epsilon, alpha=self.alpha,
                                     gamma=self.gamma, learn=self.learn)
        Duplicate.Went = self.Went
        Duplicate._trajectory = self._trajectory
        memo[id(self)] = Duplicate
        return Duplicate

    # -- Q-table access -------------------------------------------------------
    def _action_values(self, unit):
        """Return the mutable action->value dict for ``unit``'s current cell."""
        domain = domain_of(unit)
        pkey = position_key(unit.Position)
        okey = orientation_key(unit.Orientation)
        table = self.QTable[domain]
        if pkey not in table:
            seed = AIR_ACTS if domain == "air" else LAND_ACTS
            table[pkey] = {o: seed.copy() for o in ORIENTATIONS}
        if okey not in table[pkey]:
            seed = AIR_ACTS if domain == "air" else LAND_ACTS
            table[pkey][okey] = seed.copy()
        return domain, pkey, okey, table[pkey][okey]

    def _q(self, values, action):
        if action not in values:
            values[action] = 0.0
        return values[action]

    # -- Policy ---------------------------------------------------------------
    def chooseActions(self, ObservedState, State):
        """Epsilon-greedy action selection over each owned unit's legal actions."""
        Actions = []
        for UnitID, Units in ObservedState.items():
            if len(Units) == 1 and nth(Units, 0).Owner == self.ID:
                Unit = nth(Units, 0)
                ActionOptions = Unit.possibleActions(State)
                domain, pkey, okey, values = self._action_values(Unit)
                UnitActions = []
                for Options in ActionOptions:
                    if not Options:
                        continue
                    if random() < self.epsilon:
                        action = choice(list(Options))
                    else:
                        action = max(Options, key=lambda a: self._q(values, a))
                    UnitActions.append(action)
                    if self.learn:
                        self._trajectory.append((domain, pkey, okey, action))
                Actions.append((Unit.ID, UnitActions))
        return Actions

    # -- Learning -------------------------------------------------------------
    def _shaping_reward(self, domain, action):
        table = AIR_ACTS if domain == "air" else LAND_ACTS
        return table.get(action, 0.0)

    @staticmethod
    def _count_units(observed, owner_self_id):
        """Count (own_units, enemy_units) visible in an observed-state dict."""
        own, enemy = 0, 0
        for Units in observed.values():
            unit = nth(Units, 0)
            if unit is None:
                continue
            if isinstance(unit, FlagClass):
                continue
            if unit.Owner == owner_self_id:
                own += 1
            elif unit.Owner is None:
                enemy += 1
        return own, enemy

    def updateDecisionModel(self, Observations, PriorActions):
        """Per-turn TD(0) update using shaping + kill/loss reward.

        Called by the game loop each turn with this agent's observation history
        and prior actions. Performs a one-step backup for every unit that acted
        on the previous turn and is still observable.
        """
        if not self.learn or len(Observations) < 2 or len(PriorActions) < 1:
            return
        prev_obs = Observations[-2]
        cur_obs = Observations[-1]
        last_actions = PriorActions[-1]

        prev_own, prev_enemy = self._count_units(prev_obs, self.ID)
        cur_own, cur_enemy = self._count_units(cur_obs, self.ID)
        team_reward = (ENEMY_KILL_REWARD * max(0, prev_enemy - cur_enemy)
                       - FRIENDLY_LOSS_PENALTY * max(0, prev_own - cur_own))

        for (UnitID, ActionList) in last_actions:
            prev_unit = nth(prev_obs.get(UnitID, []), 0)
            if prev_unit is None:
                continue
            domain = domain_of(prev_unit)
            pkey = position_key(prev_unit.Position)
            okey = orientation_key(prev_unit.Orientation)
            self.QTable.setdefault(domain, {})
            if pkey not in self.QTable[domain]:
                seed = AIR_ACTS if domain == "air" else LAND_ACTS
                self.QTable[domain][pkey] = {o: seed.copy() for o in ORIENTATIONS}
            if okey not in self.QTable[domain][pkey]:
                seed = AIR_ACTS if domain == "air" else LAND_ACTS
                self.QTable[domain][pkey][okey] = seed.copy()
            values = self.QTable[domain][pkey][okey]

            # Bootstrap from the unit's current cell if it is still alive.
            cur_unit = nth(cur_obs.get(UnitID, []), 0)
            if cur_unit is not None and cur_unit.Position is not None:
                cdomain = domain_of(cur_unit)
                cpkey = position_key(cur_unit.Position)
                cokey = orientation_key(cur_unit.Orientation)
                nxt = self.QTable.get(cdomain, {}).get(cpkey, {}).get(cokey, {})
                max_next = max(nxt.values()) if nxt else 0.0
            else:
                max_next = 0.0

            for action in ActionList:
                reward = self._shaping_reward(domain, action) + team_reward
                old = self._q(values, action)
                values[action] = old + self.alpha * (reward + self.gamma * max_next - old)

    def finalizeEpisode(self, terminal_reward):
        """Monte-Carlo backup of ``terminal_reward`` through the trajectory.

        The terminal reward is discounted backward in time and blended into the
        Q-values of every (state, action) the agent visited this episode. Clears
        the recorded trajectory afterwards.
        """
        if not self.learn:
            self._trajectory = []
            return
        G = terminal_reward
        for (domain, pkey, okey, action) in reversed(self._trajectory):
            values = self.QTable.setdefault(domain, {}).setdefault(
                pkey, {}).setdefault(okey, {})
            old = values.get(action, 0.0)
            values[action] = old + self.alpha * (G - old)
            G *= self.gamma
        self._trajectory = []

    # -- Advisory output ------------------------------------------------------
    def recommendActions(self, ObservedState, State, topk=3):
        """Return ranked courses of action per controlled unit (advisory).

        Returns
        -------
        dict
            ``{UnitID: [(action, q_value, label), ...]}`` ordered by descending
            Q-value, at most ``topk`` entries per unit. Intended as decision
            support for a human commander, not silent auto-acting.
        """
        recommendations = {}
        for UnitID, Units in ObservedState.items():
            if len(Units) == 1 and nth(Units, 0).Owner == self.ID:
                Unit = nth(Units, 0)
                if isinstance(Unit, FlagClass):
                    continue
                ActionOptions = Unit.possibleActions(State)
                _, _, _, values = self._action_values(Unit)
                legal = []
                for Options in ActionOptions:
                    legal.extend(Options)
                ranked = sorted(legal, key=lambda a: self._q(values, a), reverse=True)
                coas = []
                for action in ranked[:topk]:
                    q = self._q(values, action)
                    label = f"{type(Unit).__name__} #{UnitID}: {action} (Q={q:+.3f})"
                    coas.append((action, q, label))
                recommendations[UnitID] = coas
        return recommendations


def save_policy(qtable, path):
    """Persist a Q-table to ``path`` as JSON (fixes the stub's no-save bug)."""
    with open(path, "w") as f:
        json.dump(qtable, f)


def load_policy(path):
    """Load a Q-table previously saved with :func:`save_policy`."""
    with open(path, "r") as f:
        return json.load(f)
