#!/usr/bin/env python3
"""Detection readiness for one advisory: coverage (can we see it?) and confidence (would it work?).

  python3 readiness.py 08-readiness-calculator.csv
"""
import csv
import sys

STATES = ["none", "telemetry", "implemented", "tested", "effective"]
rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else "08-readiness-calculator.csv")))
w = [float(r["weight_1_to_3"]) for r in rows]
v = [float(r["coverage_0_to_1"]) for r in rows]
weighted = 100 * sum(a * b for a, b in zip(w, v)) / sum(w)
full = sum(1 for r in rows if float(r["coverage_0_to_1"]) == 1 and r["maturity"] in ("tested", "effective"))
print(f"Behaviours in scope (the denominator): {len(rows)}")
print(f"Detection readiness = validated / relevant = {full} of {len(rows)} = {100 * full / len(rows):.0f}%")
print(f"Weighted coverage = sum(w*v) / sum(w) = {sum(a * b for a, b in zip(w, v)):.1f} / {sum(w):.0f} = {weighted:.0f}%")
for s in STATES[1:]:
    n = sum(1 for r in rows if STATES.index(r["maturity"]) >= STATES.index(s))
    print(f"Confidence: {n} of {len(rows)} at '{s}' or better")
