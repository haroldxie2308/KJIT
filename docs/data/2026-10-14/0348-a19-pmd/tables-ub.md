### KPTI off: a17 4 boots a19 4 boots

Server CPU per request, us, median [Q1..Q3] over all runs of the cell
| -d | test | KJIT off | a17 on | a19 on |
|---|---|---|---|---|
| 1 | SET | 3.00 [2.50..3.18] | 3.58 [3.29..3.68] | 3.49 [2.85..3.67] |
| 1 | GET | 2.84 [2.35..2.98] | 3.45 [3.27..3.61] | 3.30 [2.77..3.48] |
| 1024 | SET | 3.18 [2.60..3.45] | 4.00 [3.21..4.29] | 3.88 [3.19..4.26] |
| 1024 | GET | 3.05 [2.43..3.32] | 3.76 [3.14..3.99] | 3.60 [3.27..3.72] |

Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs (boots with a positive per-boot median / boots)
| -d | test | a19 on - a17 on | a19 on - off | a17 on - off | a19 on / off |
|---|---|---|---|---|---|
| 1 | SET | -0.120 [-0.270..+0.060] (1/4) | +0.430 [+0.355..+0.505] (4/4) | +0.550 [+0.475..+0.580] (4/4) | 1.151 [1.136..1.172] |
| 1 | GET | -0.220 [-0.325..-0.010] (1/4) | +0.430 [+0.340..+0.575] (4/4) | +0.600 [+0.555..+0.685] (4/4) | 1.168 [1.125..1.198] |
| 1024 | SET | -0.220 [-0.335..+0.000] (0/4) | +0.630 [+0.440..+0.770] (4/4) | +0.720 [+0.640..+0.825] (4/4) | 1.189 [1.162..1.235] |
| 1024 | GET | -0.220 [-0.300..-0.120] (0/4) | +0.460 [+0.330..+0.625] (4/4) | +0.670 [+0.595..+0.745] (4/4) | 1.152 [1.123..1.203] |

a19 KJIT on, after the runs (gauges), median [min..max] over runs; fragment entries per request
| -d | test | arena_chunks | arena_chunks_pmd | arena_bytes | fragment entries/req | translate_ok sum | invalidated sum |
|---|---|---|---|---|---|---|---|
| 1 | SET | 1 [1..1] | 1 [1..1] | 641496 [634640..679520] | 3.049 | 17 | 0 |
| 1 | GET | 1 [1..1] | 1 [1..1] | 641496 [635440..679520] | 3.052 | 4 | 0 |
| 1024 | SET | 1 [1..1] | 1 [1..1] | 722280 [690624..735440] | 3.047 | 6 | 0 |
| 1024 | GET | 1 [1..1] | 1 [1..1] | 722280 [690624..735440] | 3.051 | 0 | 0 |

a17: 96 on-runs, translate_ok grew in 23 (sum 29), off-runs with fragment entries: 0
a19: 96 on-runs, translate_ok grew in 19 (sum 27), off-runs with fragment entries: 0

### KPTI forced on: a17 4 boots a19 4 boots

Server CPU per request, us, median [Q1..Q3] over all runs of the cell
| -d | test | KJIT off | a17 on | a19 on |
|---|---|---|---|---|
| 1 | SET | 2.48 [2.36..3.33] | 2.93 [2.84..3.74] | 2.92 [2.86..3.55] |
| 1 | GET | 2.45 [2.28..3.17] | 2.79 [2.71..3.50] | 2.80 [2.64..3.22] |
| 1024 | SET | 2.61 [2.54..2.88] | 3.06 [3.04..3.40] | 3.08 [3.00..3.26] |
| 1024 | GET | 2.39 [2.33..2.70] | 2.87 [2.82..3.24] | 2.81 [2.74..3.23] |

Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs (boots with a positive per-boot median / boots)
| -d | test | a19 on - a17 on | a19 on - off | a17 on - off | a19 on / off |
|---|---|---|---|---|---|
| 1 | SET | -0.010 [-0.205..+0.065] (2/4) | +0.420 [+0.290..+0.500] (4/4) | +0.470 [+0.375..+0.500] (4/4) | 1.172 [1.082..1.209] |
| 1 | GET | -0.170 [-0.225..-0.035] (1/4) | +0.270 [+0.190..+0.385] (4/4) | +0.420 [+0.280..+0.460] (4/4) | 1.114 [1.060..1.170] |
| 1024 | SET | -0.050 [-0.115..+0.005] (0/4) | +0.450 [+0.395..+0.480] (4/4) | +0.540 [+0.400..+0.605] (4/4) | 1.173 [1.124..1.186] |
| 1024 | GET | -0.090 [-0.180..+0.020] (0/4) | +0.400 [+0.265..+0.465] (4/4) | +0.470 [+0.350..+0.540] (4/4) | 1.168 [1.104..1.201] |

a19 KJIT on, after the runs (gauges), median [min..max] over runs; fragment entries per request
| -d | test | arena_chunks | arena_chunks_pmd | arena_bytes | fragment entries/req | translate_ok sum | invalidated sum |
|---|---|---|---|---|---|---|---|
| 1 | SET | 1 [1..1] | 1 [1..1] | 641496 [635440..681920] | 3.051 | 9 | 0 |
| 1 | GET | 1 [1..1] | 1 [1..1] | 646696 [635440..681920] | 3.054 | 7 | 0 |
| 1024 | SET | 1 [1..1] | 1 [1..1] | 717424 [690624..735968] | 3.049 | 0 | 0 |
| 1024 | GET | 1 [1..1] | 1 [1..1] | 717424 [690624..735968] | 3.049 | 3 | 0 |

a17: 96 on-runs, translate_ok grew in 10 (sum 18), off-runs with fragment entries: 0
a19: 96 on-runs, translate_ok grew in 11 (sum 19), off-runs with fragment entries: 0

