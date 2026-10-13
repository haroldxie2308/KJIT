### KPTI forced on: main 3 boots a18 3 boots

Server CPU per request, us, median [Q1..Q3] over all runs of the cell
| -d | test | KJIT off | main on | a18 on |
|---|---|---|---|---|
| 1 | SET | 3.12 [3.08..3.16] | 3.60 [3.56..3.61] | 3.51 [3.40..3.57] |
| 1 | GET | 3.07 [3.01..3.12] | 3.52 [3.45..3.61] | 3.31 [3.25..3.35] |
| 1024 | SET | 3.29 [3.24..3.38] | 3.92 [3.85..4.04] | 3.75 [3.72..3.80] |
| 1024 | GET | 3.22 [3.17..3.30] | 3.56 [3.54..3.60] | 3.50 [3.45..3.59] |

Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs (boots with a positive per-boot median / boots)
| -d | test | a18 on - main on | a18 on - off | main on - off | a18 on / off |
|---|---|---|---|---|---|
| 1 | SET | -0.140 [-0.172..-0.047] (0/3) | +0.395 [+0.335..+0.455] (3/3) | +0.430 [+0.407..+0.520] (3/3) | 1.126 [1.109..1.147] |
| 1 | GET | -0.240 [-0.290..-0.138] (0/3) | +0.295 [+0.128..+0.395] (3/3) | +0.435 [+0.358..+0.497] (3/3) | 1.100 [1.041..1.134] |
| 1024 | SET | -0.135 [-0.290..-0.115] (1/3) | +0.485 [+0.392..+0.525] (3/3) | +0.640 [+0.573..+0.678] (3/3) | 1.150 [1.117..1.165] |
| 1024 | GET | -0.015 [-0.120..+0.075] (1/3) | +0.305 [+0.238..+0.387] (3/3) | +0.285 [+0.252..+0.317] (3/3) | 1.097 [1.073..1.121] |

a18 KJIT on, after the runs (gauges), median [min..max] over runs; fragment entries per request
| -d | test | arena_chunks | arena_bytes | fragment entries/req | translate_ok sum | invalidated sum |
|---|---|---|---|---|---|---|
| 1 | SET | 1 [1..1] | 702704 [702704..702704] | 3.069 | 0 | 0 |
| 1 | GET | 1 [1..1] | 702704 [702704..702704] | 3.079 | 0 | 0 |
| 1024 | SET | 1 [1..1] | 756224 [756224..756224] | 3.049 | 0 | 0 |
| 1024 | GET | 1 [1..1] | 756224 [756224..756224] | 3.072 | 0 | 0 |

main: 24 on-runs, translate_ok grew in 1 (sum 4), off-runs with fragment entries: 0
a18: 24 on-runs, translate_ok grew in 0 (sum 0), off-runs with fragment entries: 0

