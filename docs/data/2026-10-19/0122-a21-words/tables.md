## KPTI forced on: 12 boots (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | main | a21 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 48 | 2.167 [2.026..2.213] | 2.183 [2.019..2.213] | 2.115 [1.961..2.155] |
| unix_set_c50_p1_d1 | 18 | 2.065 [2.044..2.073] | 2.077 [2.066..2.099] | 2.023 [2.016..2.047] |
| unix_pingm_c50_p1 | 48 | 2.090 [1.946..2.131] | 2.069 [1.909..2.108] | 1.996 [1.836..2.041] |
| get_c50_p1_d1 | 18 | 2.924 [2.880..2.941] | 2.946 [2.926..2.985] | 2.904 [2.865..2.939] |
| set_c50_p1_d1 | 18 | 2.990 [2.946..3.063] | 3.134 [3.099..3.202] | 3.020 [2.983..3.058] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a21 - main | a21 - off | main - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.062 [-0.078..-0.048] (0/12 boots+, 45/48 pairs<0) | -0.059 [-0.075..-0.018] (1/12 boots+, 42/48 pairs<0) | +0.004 [-0.013..+0.028] (7/12 boots+, 21/48 pairs<0) |
| unix_set_c50_p1_d1 | -0.055 [-0.065..-0.019] (1/6 boots+, 16/18 pairs<0) | -0.030 [-0.041..+0.004] (2/6 boots+, 13/18 pairs<0) | +0.023 [+0.009..+0.037] (5/6 boots+, 4/18 pairs<0) |
| unix_pingm_c50_p1 | -0.084 [-0.097..-0.060] (0/12 boots+, 45/48 pairs<0) | -0.110 [-0.131..-0.084] (0/12 boots+, 45/48 pairs<0) | -0.021 [-0.057..-0.001] (1/12 boots+, 36/48 pairs<0) |
| get_c50_p1_d1 | -0.048 [-0.073..-0.023] (0/6 boots+, 16/18 pairs<0) | -0.005 [-0.037..+0.017] (1/6 boots+, 11/18 pairs<0) | +0.038 [+0.017..+0.058] (6/6 boots+, 2/18 pairs<0) |
| set_c50_p1_d1 | -0.127 [-0.148..-0.096] (0/6 boots+, 17/18 pairs<0) | +0.036 [-0.018..+0.061] (4/6 boots+, 5/18 pairs<0) | +0.160 [+0.125..+0.186] (5/6 boots+, 3/18 pairs<0) |

Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls (entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); freed = released_fragments; links = link slots patched / waiting (gauges, all mms)
| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | main | 276 | 0 | 256/205 | 2.148 | 3.1489 | 0.9999 | 0.0006/0.0000/1.0000/0.0007 | 2.1478/0.0000/0.0000/0.0000 | 0.00143 | 0.000008 | 602 |
| unix_get_c50_p1_d1 | a21 | 276 | 0 | 256/205 | 2.144 | 3.1450 | 0.9999 | 0.0006/0.0000/1.0000/0.0006 | 2.1438/0.0000/0.0000/0.0000 | 0.00144 | 0.000008 | 482 |
| unix_set_c50_p1_d1 | main | 297 | 0 | 282/206 | 2.174 | 3.1751 | 0.9999 | 0.0007/0.0000/0.9999/0.0003 | 2.1741/0.0000/0.0000/0.0000 | 0.00107 | 0.000002 | 636 |
| unix_set_c50_p1_d1 | a21 | 297 | 0 | 282/206 | 2.181 | 3.1823 | 0.9999 | 0.0006/0.0000/0.9999/0.0004 | 2.1813/0.0000/0.0000/0.0000 | 0.00113 | 0.000003 | 510 |
| unix_pingm_c50_p1 | main | 244 | 0 | 232/190 | 2.153 | 3.1544 | 0.9999 | 0.0009/0.0000/1.0001/0.0008 | 2.1530/0.0000/0.0000/0.0000 | 0.00197 | 0.000008 | 542 |
| unix_pingm_c50_p1 | a21 | 242 | 0 | 229/189 | 2.154 | 3.1565 | 0.9999 | 0.0009/0.0000/1.0001/0.0007 | 2.1545/0.0000/0.0000/0.0000 | 0.00196 | 0.000007 | 429 |
| get_c50_p1_d1 | main | 274 | 0 | 255/204 | 2.081 | 3.0831 | 0.9999 | 0.0010/0.0000/1.0001/0.0010 | 2.0808/0.0000/0.0000/0.0000 | 0.00235 | 0.000008 | 599 |
| get_c50_p1_d1 | a21 | 276 | 0 | 256/205 | 2.104 | 3.1056 | 0.9999 | 0.0008/0.0000/1.0001/0.0009 | 2.1036/0.0000/0.0000/0.0000 | 0.00209 | 0.000010 | 482 |
| set_c50_p1_d1 | main | 294 | 0 | 279/204 | 2.059 | 3.0613 | 1.0000 | 0.0014/0.0000/1.0002/0.0008 | 2.0594/0.0000/0.0000/0.0000 | 0.00260 | 0.000006 | 628 |
| set_c50_p1_d1 | a21 | 297 | 0 | 282/206 | 2.074 | 3.0752 | 1.0000 | 0.0009/0.0000/1.0002/0.0009 | 2.0735/0.0000/0.0000/0.0000 | 0.00224 | 0.000010 | 510 |

## KPTI off: 4 boots (1, 2, 3, 4)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | main | a21 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 12 | 1.720 [1.707..1.738] | 1.806 [1.798..1.810] | 1.773 [1.749..1.782] |
| unix_set_c50_p1_d1 | 12 | 1.743 [1.732..1.757] | 2.018 [1.950..2.046] | 1.835 [1.817..1.849] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a21 - main | a21 - off | main - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.035 [-0.054..-0.020] (0/4 boots+, 12/12 pairs<0) | +0.037 [+0.030..+0.060] (4/4 boots+, 1/12 pairs<0) | +0.088 [+0.075..+0.104] (4/4 boots+, 0/12 pairs<0) |
| unix_set_c50_p1_d1 | -0.169 [-0.222..-0.137] (0/4 boots+, 12/12 pairs<0) | +0.089 [+0.072..+0.100] (4/4 boots+, 0/12 pairs<0) | +0.264 [+0.206..+0.306] (4/4 boots+, 0/12 pairs<0) |

Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls (entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); freed = released_fragments; links = link slots patched / waiting (gauges, all mms)
| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | main | 276 | 0 | 256/205 | 2.108 | 3.1090 | 0.9999 | 0.0005/0.0000/0.9999/0.0005 | 2.1082/0.0000/0.0000/0.0000 | 0.00111 | 0.000005 | 602 |
| unix_get_c50_p1_d1 | a21 | 276 | 0 | 256/205 | 2.149 | 3.1503 | 0.9999 | 0.0005/0.0000/0.9999/0.0005 | 2.1495/0.0000/0.0000/0.0000 | 0.00108 | 0.000005 | 482 |
| unix_set_c50_p1_d1 | main | 297 | 0 | 282/206 | 2.067 | 3.0678 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.0667/0.0000/0.0000/0.0000 | 0.00116 | 0.000005 | 636 |
| unix_set_c50_p1_d1 | a21 | 297 | 0 | 282/206 | 2.086 | 3.0866 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.0856/0.0000/0.0000/0.0000 | 0.00114 | 0.000005 | 510 |

