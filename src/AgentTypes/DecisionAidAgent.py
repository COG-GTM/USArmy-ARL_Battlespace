# -*- coding: utf-8 -*-
"""
Optional aid-in-the-loop agent.

``TeamDecisionAidAgentClass`` plays through the headless harness using the WS3
decision aids: each turn it scores visible enemy threats (``ThreatModel``) and
computes a weapon-to-target assignment (``Assignment``), then engages assigned
targets (ram when adjacent, shoot when oriented on-target) and otherwise falls
back to uniform-random movement. It demonstrates the aid driving real play; it
is intentionally a thin heuristic (no path-planning), not a tuned combat policy.
"""

import itertools
from random import choice

from src.AgentTypes.TeamAgents import TeamUniformRandomAgentClass
from src.UnitTypes.ExampleUnit import FlagClass
from src.DecisionAid import ThreatModel, Assignment


def nth(iterable, n, default=None):
    return next(itertools.islice(iterable, n, None), default)


def _sign(v):
    return (v > 0) - (v < 0)


class TeamDecisionAidAgentClass(TeamUniformRandomAgentClass):
    def updateDecisionModel(self, Observations, PriorActions):
        pass

    def chooseActions(self, ObservedState, State):
        threats = ThreatModel.score(ObservedState, State, self.ID)
        friendly = ThreatModel.friendly_units(ObservedState, self.ID)
        assignments = Assignment.optimize(friendly, threats)
        target_by_friendly = {a["friendly_id"]: a for a in assignments}
        threat_by_id = {t["unit_id"]: t for t in threats}

        Actions = []
        for UnitID, Units in ObservedState.items():
            if not (len(Units) == 1 and nth(Units, 0).Owner == self.ID):
                continue
            Unit = nth(Units, 0)
            if isinstance(Unit, FlagClass):
                continue
            legal = []
            for Options in Unit.possibleActions(State):
                legal.extend(Options)

            action = self._engage_action(Unit, UnitID, legal,
                                         target_by_friendly, threat_by_id)
            if action is None:
                action = choice(legal) if legal else "doNothing"
            Actions.append((Unit.ID, [action]))
        return Actions

    def _engage_action(self, unit, unit_id, legal, target_by_friendly, threat_by_id):
        """Return an engagement action toward the assigned target, or None."""
        assignment = target_by_friendly.get(unit_id)
        if assignment is None:
            return None
        target = threat_by_id.get(assignment["target_id"])
        if target is None or unit.Position is None:
            return None

        px, py = int(unit.Position[0]), int(unit.Position[1])
        tx, ty = target["position"][0], target["position"][1]
        dx, dy = tx - px, ty - py
        distance = max(abs(dx), abs(dy))

        if distance <= 1 and "ram" in legal:
            return "ram"
        if "shoot" in legal and unit.Orientation is not None:
            ox, oy = int(unit.Orientation[0]), int(unit.Orientation[1])
            if (ox, oy) == (_sign(dx), _sign(dy)) and (dx or dy):
                return "shoot"
        return None
