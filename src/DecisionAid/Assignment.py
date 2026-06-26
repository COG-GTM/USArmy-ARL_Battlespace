# -*- coding: utf-8 -*-
"""
Weapon-to-target assignment decision aid for ARL Battlespace.

Given the agent's friendly units and a ranked list of enemy threats (from
``ThreatModel``), ``optimize`` builds a friendly x enemy utility matrix and
solves the assignment problem so each weapon (friendly unit) is paired with the
target it should engage this turn.

Utility of pairing friendly *f* against enemy *e* is::

    utility(f, e) = Pk(f -> e) * threat(e)

i.e. prefer pairings where we can actually score a kill (high Pk) against the
most dangerous enemies (high threat). The optimal one-to-one assignment is found
with the Hungarian algorithm (``scipy.optimize.linear_sum_assignment``) when
SciPy is available, falling back to a documented greedy matcher otherwise.
"""

from src.DecisionAid.ThreatModel import pk_estimate

try:
    from scipy.optimize import linear_sum_assignment
    _HAVE_SCIPY = True
except ImportError:  # pragma: no cover - exercised only without SciPy
    linear_sum_assignment = None
    _HAVE_SCIPY = False


def build_utility_matrix(friendly_units, enemy_threats):
    """Return the ``len(friendly) x len(enemy)`` utility matrix.

    ``utility[i][j] = Pk(friendly_i -> enemy_j) * threat(enemy_j)``.
    """
    matrix = []
    for f in friendly_units:
        row = []
        for e in enemy_threats:
            pk = pk_estimate(f["unit_type"], f["position"], e["position"])
            row.append(pk * e["threat"])
        matrix.append(row)
    return matrix


def _greedy_assignment(matrix):
    """Greedy fallback matcher: repeatedly take the globally best free pairing.

    Documented fallback used when SciPy is unavailable. Not guaranteed optimal,
    but produces a valid one-to-one assignment.
    """
    pairs = []
    used_rows, used_cols = set(), set()
    candidates = []
    for i, row in enumerate(matrix):
        for j, val in enumerate(row):
            candidates.append((val, i, j))
    candidates.sort(reverse=True)
    for val, i, j in candidates:
        if i in used_rows or j in used_cols:
            continue
        used_rows.add(i)
        used_cols.add(j)
        pairs.append((i, j))
    return pairs


def optimize(friendly_units, enemy_threats):
    """Solve weapon-to-target assignment for one turn.

    Parameters
    ----------
    friendly_units : list[dict]
        Friendly units (from ``ThreatModel.friendly_units``).
    enemy_threats : list[dict]
        Ranked enemy threats (from ``ThreatModel.score``).

    Returns
    -------
    list[dict]
        One entry per assigned friendly unit, each with ``friendly_id``,
        ``friendly_type``, ``target_id``, ``target_type``, ``pk``, ``utility``
        and a one-line ``rationale``. Assignment is one-to-one (a unit is paired
        with at most one target and vice-versa).
    """
    if not friendly_units or not enemy_threats:
        return []

    matrix = build_utility_matrix(friendly_units, enemy_threats)

    if _HAVE_SCIPY:
        # Hungarian algorithm minimises cost; negate utility to maximise it.
        cost = [[-v for v in row] for row in matrix]
        row_idx, col_idx = linear_sum_assignment(cost)
        index_pairs = list(zip(row_idx.tolist(), col_idx.tolist()))
        solver = "hungarian"
    else:
        index_pairs = _greedy_assignment(matrix)
        solver = "greedy"

    assignments = []
    for i, j in index_pairs:
        f = friendly_units[i]
        e = enemy_threats[j]
        pk = pk_estimate(f["unit_type"], f["position"], e["position"])
        utility = matrix[i][j]
        rationale = (f"{f['unit_type']} #{f['unit_id']} -> enemy "
                     f"{e['unit_type']} #{e['unit_id']} "
                     f"(Pk {pk:.2f}, target threat {e['threat']:.2f}, "
                     f"utility {utility:.2f})")
        assignments.append({
            "friendly_id": f["unit_id"],
            "friendly_type": f["unit_type"],
            "target_id": e["unit_id"],
            "target_type": e["unit_type"],
            "pk": pk,
            "utility": utility,
            "solver": solver,
            "rationale": rationale,
        })

    # Present the highest-value engagements first.
    assignments.sort(key=lambda a: a["utility"], reverse=True)
    return assignments
