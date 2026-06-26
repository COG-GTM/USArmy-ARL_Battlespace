# -*- coding: utf-8 -*-
"""
Threat prioritization decision aid for ARL Battlespace.

Given an agent's (limited-visibility) observed state, ``score`` ranks every
*visible* enemy unit by the threat it poses to the agent's flag, combining:

(a) **Proximity to the friendly flag** -- an enemy near our flag is dangerous
    because ground units (Soldier/Tank/Truck) capture a flag simply by moving
    onto it, which removes the entire owning team (see flag-capture rules in
    ``TeamCaptureFlagGame.resolveActions``).
(b) **Unit-type weight** -- direct-fire and capture capability differ by type.
(c) **Probability of kill (Pk)** -- a combat-model estimate of how readily the
    enemy can reach/engage our flag this turn, derived from its movement reach
    (``AdvanceRange``) and lethal shot/ram mechanics (a single hit destroys a
    health-1 unit; see ``GroundUnitModule.shoot`` and ``UnitModule.ram``).

Only enemies actually present in ``ObservedState`` are scored, respecting the
game's fog of war.
"""

from src.UnitTypes.ExampleUnit import FlagClass

# Per-unit-type combat profile.
#   threat_weight : relative danger of the unit type (Tank strongest direct fire).
#   advance       : cells the unit can close per turn (AdvanceRange).
#   can_capture   : whether the unit can capture a flag (ground units only).
#   can_shoot     : whether the unit can fire a lethal projectile.
UNIT_PROFILE = {
    "TankClass":     {"threat_weight": 1.00, "advance": 1, "can_capture": True,  "can_shoot": True},
    "SoldierClass":  {"threat_weight": 0.80, "advance": 1, "can_capture": True,  "can_shoot": True},
    "TruckClass":    {"threat_weight": 0.70, "advance": 1, "can_capture": True,  "can_shoot": True},
    "AirplaneClass": {"threat_weight": 0.60, "advance": 2, "can_capture": False, "can_shoot": True},
}
DEFAULT_PROFILE = {"threat_weight": 0.50, "advance": 1, "can_capture": False, "can_shoot": False}

# Weights blending flag-proximity and offensive Pk into the threat score.
W_PROXIMITY = 0.5
W_PK = 0.5


def chebyshev(a, b):
    """Chebyshev (king-move) distance in the XY plane.

    Movement allows diagonals (turn 45 deg then advance), so king-move distance
    is the natural measure of how many turns a unit needs to close a gap.
    """
    return max(abs(int(a[0]) - int(b[0])), abs(int(a[1]) - int(b[1])))


def profile_for(unit_type_name):
    return UNIT_PROFILE.get(unit_type_name, DEFAULT_PROFILE)


def pk_estimate(attacker_type_name, attacker_position, target_position):
    """Estimate the probability that ``attacker`` kills/reaches a target this turn.

    Modeled from the combat mechanics: a unit is lethal on contact (ram) or via
    a projectile, and every unit has health 1 so a single hit is fatal. The
    achievable Pk this turn therefore falls off with the distance the attacker
    must cover relative to its movement reach. The result is in ``[0, 1]`` and is
    monotonically non-increasing in distance and non-decreasing in unit strength.

    Returns 0 for units with no offensive capability.
    """
    profile = profile_for(attacker_type_name)
    if not (profile["can_shoot"] or profile["can_capture"]):
        return 0.0
    distance = chebyshev(attacker_position, target_position)
    reach = profile["advance"]
    if distance <= reach:
        # Within a single move: contact/capture is essentially assured.
        base = 1.0
    else:
        # Beyond reach: decays with how many extra cells must be closed.
        base = 1.0 / (1.0 + (distance - reach))
    return profile["threat_weight"] * base


def score(ObservedState, State, agentID, friendly_flag_position=None):
    """Rank visible enemy units by threat to the agent's flag.

    Parameters
    ----------
    ObservedState : dict
        ``{UnitID: set(UnitClass)}`` as produced by ``TeamCaptureFlagGame.observe``.
        Enemy units appear with ``Owner is None`` but retain their concrete type.
    State : TeamStateClass
        Ground-truth state (used only for ``FlagPosition`` lookup).
    agentID : int
        The agent whose flag is being defended.
    friendly_flag_position : tuple, optional
        Override for the friendly flag position. Defaults to
        ``State.FlagPosition[agentID]`` when available.

    Returns
    -------
    list[dict]
        One entry per visible enemy, sorted by descending ``threat``. Each entry
        contains ``unit_id``, ``unit_type``, ``position``, ``flag_distance``,
        ``pk``, ``threat`` and a one-line ``rationale``.
    """
    if friendly_flag_position is None and getattr(State, "FlagPosition", None):
        friendly_flag_position = State.FlagPosition.get(agentID)

    threats = []
    for UnitID, Units in ObservedState.items():
        unit = next(iter(Units), None) if Units else None
        if unit is None or unit.Position is None:
            continue
        # Enemy units are reported with Owner = None by the game's observe().
        if unit.Owner is not None:
            continue
        unit_type = type(unit).__name__
        profile = profile_for(unit_type)

        if friendly_flag_position is not None:
            flag_distance = chebyshev(unit.Position, friendly_flag_position)
            proximity = 1.0 / (1.0 + flag_distance)
            pk = pk_estimate(unit_type, unit.Position, friendly_flag_position)
        else:
            flag_distance = None
            proximity = 0.0
            pk = 0.0

        threat = profile["threat_weight"] * (W_PROXIMITY * proximity + W_PK * pk)

        dist_text = "unknown" if flag_distance is None else str(flag_distance)
        rationale = (f"{unit_type} #{UnitID} at {tuple(int(c) for c in unit.Position)}: "
                     f"threat={threat:.2f} (flag dist {dist_text}, Pk {pk:.2f}, "
                     f"type wt {profile['threat_weight']:.2f}"
                     f"{', can capture flag' if profile['can_capture'] else ''})")

        threats.append({
            "unit_id": UnitID,
            "unit_type": unit_type,
            "position": tuple(int(c) for c in unit.Position),
            "flag_distance": flag_distance,
            "pk": pk,
            "threat": threat,
            "rationale": rationale,
        })

    threats.sort(key=lambda t: t["threat"], reverse=True)
    return threats


def friendly_units(ObservedState, agentID):
    """Extract the agent's own living units from an observed state.

    Returns a list of dicts ``{unit_id, unit_type, position, unit}`` for units
    owned by ``agentID`` (excludes flags, which cannot engage).
    """
    units = []
    for UnitID, Units in ObservedState.items():
        unit = next(iter(Units), None) if Units else None
        if unit is None or unit.Position is None:
            continue
        if unit.Owner == agentID and not isinstance(unit, FlagClass):
            units.append({
                "unit_id": UnitID,
                "unit_type": type(unit).__name__,
                "position": tuple(int(c) for c in unit.Position),
                "unit": unit,
            })
    return units
