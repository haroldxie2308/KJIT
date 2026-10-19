## KPTI forced on: 12 boots (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | a21 | a22 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 48 | 1.976 [1.969..1.991] | 1.934 [1.915..1.950] | 1.909 [1.895..1.923] |
| unix_set_c50_p1_d1 | 18 | 2.034 [2.013..2.043] | 2.021 [2.012..2.030] | 1.992 [1.976..2.002] |
| unix_pingm_c50_p1 | 48 | 1.919 [1.905..1.933] | 1.810 [1.798..1.823] | 1.804 [1.791..1.820] |
| get_c50_p1_d1 | 18 | 2.903 [2.882..2.913] | 2.899 [2.866..2.916] | 2.863 [2.830..2.895] |
| set_c50_p1_d1 | 18 | 2.979 [2.964..3.003] | 3.033 [2.991..3.049] | 3.001 [2.965..3.022] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a22 - a21 | a22 - off | a21 - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.026 [-0.042..+0.001] (2/12 boots+, 36/48 pairs<0) | -0.074 [-0.083..-0.056] (0/12 boots+, 48/48 pairs<0) | -0.044 [-0.059..-0.030] (0/12 boots+, 47/48 pairs<0) |
| unix_set_c50_p1_d1 | -0.042 [-0.047..-0.026] (1/6 boots+, 14/18 pairs<0) | -0.044 [-0.051..-0.018] (0/6 boots+, 17/18 pairs<0) | -0.008 [-0.020..+0.005] (1/6 boots+, 13/18 pairs<0) |
| unix_pingm_c50_p1 | -0.004 [-0.027..+0.011] (5/12 boots+, 28/48 pairs<0) | -0.114 [-0.132..-0.097] (0/12 boots+, 48/48 pairs<0) | -0.108 [-0.130..-0.092] (0/12 boots+, 48/48 pairs<0) |
| get_c50_p1_d1 | -0.033 [-0.055..-0.015] (0/6 boots+, 15/18 pairs<0) | -0.026 [-0.061..-0.010] (1/6 boots+, 15/18 pairs<0) | +0.001 [-0.017..+0.014] (3/6 boots+, 9/18 pairs<0) |
| set_c50_p1_d1 | -0.029 [-0.064..+0.022] (2/6 boots+, 11/18 pairs<0) | +0.032 [-0.025..+0.051] (3/6 boots+, 7/18 pairs<0) | +0.033 [+0.003..+0.062] (5/6 boots+, 4/18 pairs<0) |

Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls (entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); freed = released_fragments; links = link slots patched / waiting (gauges, all mms)
| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | a21 | 276 | 0 | 256/205 | 2.144 | 3.1449 | 0.9999 | 0.0006/0.0000/0.9999/0.0006 | 2.1439/0.0000/0.0000/0.0000 | 0.00137 | 0.000008 | 482 |
| unix_get_c50_p1_d1 | a22 | 276 | 0 | 256/205 | 2.145 | 3.1457 | 0.9999 | 0.0006/0.0000/0.9999/0.0007 | 2.1448/0.0000/0.0000/0.0000 | 0.00139 | 0.000009 | 451 |
| unix_set_c50_p1_d1 | a21 | 297 | 0 | 282/206 | 2.188 | 3.1889 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.1879/0.0000/0.0000/0.0000 | 0.00125 | 0.000005 | 510 |
| unix_set_c50_p1_d1 | a22 | 297 | 0 | 282/206 | 2.151 | 3.1524 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.1512/0.0000/0.0000/0.0000 | 0.00124 | 0.000005 | 477 |
| unix_pingm_c50_p1 | a21 | 240 | 0 | 226/188 | 2.157 | 3.1590 | 0.9999 | 0.0009/0.0000/1.0000/0.0006 | 2.1573/0.0000/0.0000/0.0000 | 0.00179 | 0.000005 | 427 |
| unix_pingm_c50_p1 | a22 | 239 | 0 | 226/183 | 2.157 | 3.1590 | 0.9999 | 0.0009/0.0000/1.0001/0.0006 | 2.1574/0.0000/0.0000/0.0000 | 0.00183 | 0.000005 | 390 |
| get_c50_p1_d1 | a21 | 276 | 0 | 256/205 | 2.099 | 3.1009 | 0.9999 | 0.0008/0.0000/1.0001/0.0009 | 2.0989/0.0000/0.0000/0.0000 | 0.00198 | 0.000010 | 482 |
| get_c50_p1_d1 | a22 | 276 | 0 | 256/205 | 2.119 | 3.1205 | 0.9999 | 0.0008/0.0000/1.0000/0.0009 | 2.1187/0.0000/0.0000/0.0000 | 0.00190 | 0.000010 | 451 |
| set_c50_p1_d1 | a21 | 297 | 0 | 282/206 | 2.073 | 3.0744 | 1.0000 | 0.0009/0.0000/1.0001/0.0011 | 2.0731/0.0000/0.0000/0.0000 | 0.00230 | 0.000009 | 510 |
| set_c50_p1_d1 | a22 | 297 | 0 | 282/206 | 2.078 | 3.0800 | 1.0000 | 0.0008/0.0000/1.0001/0.0009 | 2.0780/0.0000/0.0000/0.0000 | 0.00202 | 0.000010 | 477 |

## KPTI off: 4 boots (1, 2, 3, 4)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | a21 | a22 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 12 | 1.697 [1.683..1.707] | 1.753 [1.745..1.766] | 1.764 [1.737..1.772] |
| unix_set_c50_p1_d1 | 12 | 1.738 [1.726..1.750] | 1.817 [1.812..1.827] | 1.796 [1.793..1.816] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a22 - a21 | a22 - off | a21 - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | +0.014 [-0.014..+0.028] (2/4 boots+, 5/12 pairs<0) | +0.062 [+0.036..+0.081] (4/4 boots+, 1/12 pairs<0) | +0.063 [+0.044..+0.075] (4/4 boots+, 1/12 pairs<0) |
| unix_set_c50_p1_d1 | -0.017 [-0.031..+0.008] (1/4 boots+, 8/12 pairs<0) | +0.064 [+0.053..+0.091] (4/4 boots+, 0/12 pairs<0) | +0.082 [+0.067..+0.094] (4/4 boots+, 0/12 pairs<0) |

Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls (entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); freed = released_fragments; links = link slots patched / waiting (gauges, all mms)
| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | a21 | 276 | 0 | 256/205 | 2.143 | 3.1443 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.1433/0.0000/0.0000/0.0000 | 0.00117 | 0.000006 | 482 |
| unix_get_c50_p1_d1 | a22 | 276 | 0 | 256/205 | 2.162 | 3.1629 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.1620/0.0000/0.0000/0.0000 | 0.00110 | 0.000005 | 451 |
| unix_set_c50_p1_d1 | a21 | 297 | 0 | 282/206 | 2.085 | 3.0857 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.0846/0.0000/0.0000/0.0000 | 0.00115 | 0.000004 | 510 |
| unix_set_c50_p1_d1 | a22 | 297 | 0 | 282/206 | 2.102 | 3.1028 | 0.9999 | 0.0007/0.0000/0.9999/0.0004 | 2.1018/0.0000/0.0000/0.0000 | 0.00106 | 0.000002 | 477 |

