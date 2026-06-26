# -*- coding: utf-8 -*-
"""
Deterministic unit tests for the threat-prioritization and weapon-to-target
assignment decision aids (WS3).

Run with::

    python -m unittest test.test_decision_aid -v
"""

import unittest

from src.StateTypes.TeamState import TeamStateClass
from src.UnitTypes.SoldierModule import SoldierClass
from src.UnitTypes.TankModule import TankClass
from src.UnitTypes.TruckModule import TruckClass
from src.DecisionAid import ThreatModel, Assignment


AGENT_ID = 0
FLAG_POS = (5, 5, 0)


def make_state(flag_pos=FLAG_POS, agent_id=AGENT_ID):
    state = TeamStateClass()
    state.FlagPosition = {agent_id: flag_pos}
    state.BoardSize = (10, 11, 2)
    return state


def enemy(unit_cls, unit_id, position):
    """Build a visible enemy unit (Owner=None as produced by observe())."""
    u = unit_cls(unit_id, None, 1, Position=position, Orientation=(0, 1, 0))
    return u


def friendly(unit_cls, unit_id, position, agent_id=AGENT_ID):
    return unit_cls(unit_id, agent_id, 1, Position=position, Orientation=(0, 1, 0))


def observed(units):
    """Wrap units into the ObservedState dict shape {UnitID: {unit}}."""
    return {u.ID: {u} for u in units}


class ThreatOrderingTests(unittest.TestCase):
    def test_closer_enemy_outranks_farther_same_type(self):
        state = make_state()
        near = enemy(SoldierClass, 10, (5, 6, 0))   # adjacent to flag
        far = enemy(SoldierClass, 11, (0, 0, 0))     # corner
        threats = ThreatModel.score(observed([near, far]), state, AGENT_ID)
        self.assertEqual(threats[0]["unit_id"], 10)
        self.assertGreater(threats[0]["threat"], threats[1]["threat"])

    def test_stronger_type_outranks_weaker_same_distance(self):
        state = make_state()
        tank = enemy(TankClass, 20, (5, 7, 0))
        truck = enemy(TruckClass, 21, (5, 3, 0))     # symmetric distance to flag
        threats = ThreatModel.score(observed([tank, truck]), state, AGENT_ID)
        self.assertEqual(threats[0]["unit_type"], "TankClass")
        self.assertGreater(threats[0]["threat"], threats[1]["threat"])

    def test_only_visible_enemies_scored(self):
        state = make_state()
        en = enemy(TankClass, 30, (5, 6, 0))
        fr = friendly(SoldierClass, 1, (5, 4, 0))
        threats = ThreatModel.score(observed([en, fr]), state, AGENT_ID)
        ids = {t["unit_id"] for t in threats}
        self.assertIn(30, ids)
        self.assertNotIn(1, ids)  # friendly units are not threats


class PkMonotonicityTests(unittest.TestCase):
    def test_pk_decreases_with_distance(self):
        close = ThreatModel.pk_estimate("TankClass", (5, 5, 0), (5, 6, 0))
        mid = ThreatModel.pk_estimate("TankClass", (5, 5, 0), (5, 9, 0))
        far = ThreatModel.pk_estimate("TankClass", (5, 5, 0), (5, 0, 0))
        self.assertGreaterEqual(close, mid)
        self.assertGreaterEqual(mid, far)

    def test_pk_increases_with_strength(self):
        tank = ThreatModel.pk_estimate("TankClass", (0, 0, 0), (0, 5, 0))
        truck = ThreatModel.pk_estimate("TruckClass", (0, 0, 0), (0, 5, 0))
        self.assertGreater(tank, truck)

    def test_pk_bounded(self):
        pk = ThreatModel.pk_estimate("TankClass", (5, 5, 0), (5, 5, 0))
        self.assertLessEqual(pk, 1.0)
        self.assertGreaterEqual(pk, 0.0)


class AssignmentValidityTests(unittest.TestCase):
    def _setup(self):
        state = make_state()
        enemies = [enemy(TankClass, 40, (5, 6, 0)),
                   enemy(SoldierClass, 41, (2, 2, 0)),
                   enemy(TruckClass, 42, (8, 8, 0))]
        friendlies = [friendly(SoldierClass, 1, (5, 4, 0)),
                      friendly(TankClass, 2, (3, 3, 0))]
        threats = ThreatModel.score(observed(enemies), state, AGENT_ID)
        fr = ThreatModel.friendly_units(observed(friendlies), AGENT_ID)
        return threats, fr

    def test_one_to_one_assignment(self):
        threats, fr = self._setup()
        assignments = Assignment.optimize(fr, threats)
        friendly_ids = [a["friendly_id"] for a in assignments]
        target_ids = [a["target_id"] for a in assignments]
        # No friendly or target used twice.
        self.assertEqual(len(friendly_ids), len(set(friendly_ids)))
        self.assertEqual(len(target_ids), len(set(target_ids)))
        # At most min(#friendly, #enemy) pairings.
        self.assertLessEqual(len(assignments), min(len(fr), len(threats)))

    def test_assignment_pairs_are_valid_units(self):
        threats, fr = self._setup()
        assignments = Assignment.optimize(fr, threats)
        valid_friendly = {f["unit_id"] for f in fr}
        valid_enemy = {t["unit_id"] for t in threats}
        for a in assignments:
            self.assertIn(a["friendly_id"], valid_friendly)
            self.assertIn(a["target_id"], valid_enemy)
            self.assertGreaterEqual(a["pk"], 0.0)

    def test_empty_inputs(self):
        self.assertEqual(Assignment.optimize([], []), [])

    def test_utility_matrix_shape(self):
        threats, fr = self._setup()
        matrix = Assignment.build_utility_matrix(fr, threats)
        self.assertEqual(len(matrix), len(fr))
        for row in matrix:
            self.assertEqual(len(row), len(threats))


if __name__ == "__main__":
    unittest.main()
