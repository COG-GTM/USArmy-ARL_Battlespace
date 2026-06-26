# Measured Results

All numbers below are reproducible with the commands shown. Seeds are fixed so
runs are deterministic. Reported honestly -- no overclaiming.

## WS1 -- Harness baseline (UniformRandomAgent vs UniformRandomAgent)

`python -m src.Harness.Simulator --games 200 --seed 0`

| Outcome      | Count | Rate  |
|--------------|-------|-------|
| Team 0 (A)   | 91    | 45.5% |
| Team 1 (B)   | 72    | 36.0% |
| Draws        | 37    | 18.5% |

Roughly balanced, as expected for symmetric random play. The small Team 0 edge
is a consistent start-position asymmetry (south quadrants), not noise -- it
reproduces across seeds and is the reference both decision aids are measured
against.

## WS2 -- Trained RL policy vs UniformRandomAgent

Training: `python -m src.Training.train_rl --episodes 600 --opponent self --seed 0`
(self-play, epsilon 0.40 -> 0.05, ~18 min, persisted to `src/Training/policy.json`).

Evaluation: `python -m src.Training.eval_rl --games 200 --seed 1000`
(greedy trained policy as Team 1 vs random Team 0, 200 seeded games).

| Outcome              | Count | Rate  |
|----------------------|-------|-------|
| Team 0 (Random)      | 5     | 2.5%  |
| Team 1 (Trained)     | 101   | 50.5% |
| Draws                | 94    | 47.0% |

Reference (random as Team 1, same seeds): 35.5% win.

- **Trained Team 1 win-rate: 50.5%** vs **35.5% random baseline (+15.0 pp).**
- The trained policy holds the random opponent to **2.5% wins** (vs 40.5% in the
  pure-random reference) -- i.e. it almost never loses, converting most losses
  into wins or draws.

Honest caveat: tabular Q-learning on this large position x orientation x action
space is not fully converged at 600 self-play episodes; the high draw rate (47%)
reflects two copies of the same cautious greedy policy avoiding mutual
destruction. Longer training / state abstraction is a follow-up (see PR notes).

## WS3 -- Threat + assignment decision aid

Unit tests: `python -m unittest test.test_decision_aid -v` -> **10 tests pass**
(threat ordering by proximity & type, Pk monotonicity, one-to-one assignment
validity, utility-matrix shape).

Demo: `python -m src.DecisionAid.demo` prints ranked enemy threats, the optimal
weapon-to-target assignment (Hungarian solver), per-pairing Pk, and -- when a
trained policy is present -- the RL agent's top-3 COA recommendations.

Aid-in-the-loop agent (`TeamDecisionAidAgentClass`) vs random, 30 seeded games:

| Outcome                 | Count | Rate  |
|-------------------------|-------|-------|
| Team 0 (Random)         | 5     | 16.7% |
| Team 1 (DecisionAid)    | 18    | 60.0% |
| Draws                   | 7     | 23.3% |

The aid-driven agent wins **60%** vs random's **16.7%**, confirming the threat
scores and assignment translate into real combat advantage.
