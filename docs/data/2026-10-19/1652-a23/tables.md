## KPTI forced on: 6 boots (1, 2, 3, 4, 5, 6)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | main | a23 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 24 | 1.985 [1.974..1.996] | 1.912 [1.898..1.931] | 1.863 [1.856..1.878] |
| unix_set_c50_p1_d1 | 24 | 2.027 [2.018..2.053] | 1.984 [1.977..1.995] | 1.945 [1.937..1.954] |
| unix_pingm_c50_p1 | 24 | 1.922 [1.909..1.940] | 1.804 [1.792..1.823] | 1.757 [1.749..1.764] |
| get_c50_p1_d1 | 24 | 2.882 [2.857..2.914] | 2.852 [2.840..2.881] | 2.806 [2.785..2.847] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a23 - main | a23 - off | main - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.045 [-0.063..-0.036] (0/6 boots+, 23/24 pairs<0) | -0.120 [-0.134..-0.108] (0/6 boots+, 23/24 pairs<0) | -0.074 [-0.087..-0.059] (0/6 boots+, 23/24 pairs<0) |
| unix_set_c50_p1_d1 | -0.038 [-0.055..-0.016] (0/6 boots+, 21/24 pairs<0) | -0.085 [-0.100..-0.075] (0/6 boots+, 24/24 pairs<0) | -0.048 [-0.059..-0.037] (0/6 boots+, 24/24 pairs<0) |
| unix_pingm_c50_p1 | -0.048 [-0.066..-0.035] (0/6 boots+, 24/24 pairs<0) | -0.170 [-0.182..-0.152] (0/6 boots+, 24/24 pairs<0) | -0.118 [-0.133..-0.091] (0/6 boots+, 24/24 pairs<0) |
| get_c50_p1_d1 | -0.039 [-0.061..-0.024] (0/6 boots+, 20/24 pairs<0) | -0.067 [-0.098..-0.041] (0/6 boots+, 24/24 pairs<0) | -0.036 [-0.064..+0.003] (0/6 boots+, 18/24 pairs<0) |

Per request, median over runs (counters of the loaded module); exits = bl/blr/br/ret; brackets = fpsimd_entries; boundary = ibtc_fpsimd_boundary; sticky = fp_sticky_set (per run); mem = fpsimd_exit_mem; declined = run_declined; ibtc misses = cold+conflict+other; insert = ibtc_insert (slot stores); fragments = translate_ok since the module was loaded (warm-ups included, the cell's server)
| cell | state | fragments | in-kernel syscalls | fragment entries | brackets | boundary | sticky | chains | exit bl/blr/br/ret | exit svc/mem/unsup/budget | mem (bracketed) | declined | ibtc misses | insert |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | main | 276 | 2.145 | 3.1463 | 0.9999 | 0.99987 | 0 | 0.9999 | 0.0006/0.0000/0.9999/0.0007 | 2.1454/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00138 | 0.00001 |
| unix_get_c50_p1_d1 | a23 | 276 | 2.157 | 2.1579 | 1.0000 | 0.00000 | 1 | 0.0000 | 0.0006/0.0000/0.0001/0.0007 | 2.1566/0.0000/0.0000/0.0000 | 0.00001 | 0.00004 | 0.00134 | 0.00001 |
| unix_set_c50_p1_d1 | main | 297 | 2.158 | 3.1597 | 0.9999 | 0.99992 | 0 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.1585/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00119 | 0.00001 |
| unix_set_c50_p1_d1 | a23 | 297 | 2.142 | 2.1430 | 1.0000 | 0.00000 | 1 | 0.0000 | 0.0007/0.0000/0.0000/0.0005 | 2.1418/0.0000/0.0000/0.0000 | 0.00001 | 0.00004 | 0.00120 | 0.00001 |
| unix_pingm_c50_p1 | main | 239 | 2.158 | 3.1595 | 0.9999 | 0.99986 | 0 | 0.9999 | 0.0009/0.0000/1.0001/0.0006 | 2.1578/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00181 | 0.00001 |
| unix_pingm_c50_p1 | a23 | 238 | 2.154 | 2.1553 | 0.9999 | 0.00000 | 0 | 0.0000 | 0.0009/0.0000/0.0002/0.0005 | 2.1536/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00176 | 0.00000 |
| get_c50_p1_d1 | main | 276 | 2.112 | 3.1141 | 0.9999 | 0.99991 | 0 | 0.9999 | 0.0007/0.0000/1.0000/0.0008 | 2.1123/0.0000/0.0000/0.0000 | 0.00000 | 0.00005 | 0.00179 | 0.00001 |
| get_c50_p1_d1 | a23 | 276 | 2.132 | 2.1331 | 1.0000 | 0.00000 | 1 | 0.0000 | 0.0006/0.0000/0.0001/0.0007 | 2.1317/0.0000/0.0000/0.0000 | 0.00000 | 0.00005 | 0.00153 | 0.00001 |

## KPTI off: 8 boots (1, 2, 3, 4, 5, 6, 7, 8)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | main | a23 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 32 | 1.712 [1.701..1.720] | 1.764 [1.744..1.775] | 1.732 [1.726..1.744] |
| unix_set_c50_p1_d1 | 32 | 1.730 [1.714..1.744] | 1.801 [1.792..1.812] | 1.774 [1.764..1.781] |
| unix_pingm_c50_p1 | 32 | 1.653 [1.638..1.665] | 1.711 [1.703..1.721] | 1.652 [1.638..1.665] |
| get_c50_p1_d1 | 32 | 2.676 [2.631..2.710] | 2.830 [2.812..2.857] | 2.754 [2.731..2.773] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a23 - main | a23 - off | main - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.027 [-0.046..-0.008] (1/8 boots+, 26/32 pairs<0) | +0.016 [+0.011..+0.032] (8/8 boots+, 2/32 pairs<0) | +0.049 [+0.030..+0.075] (8/8 boots+, 2/32 pairs<0) |
| unix_set_c50_p1_d1 | -0.029 [-0.045..-0.017] (0/8 boots+, 29/32 pairs<0) | +0.040 [+0.030..+0.059] (8/8 boots+, 1/32 pairs<0) | +0.069 [+0.061..+0.082] (8/8 boots+, 0/32 pairs<0) |
| unix_pingm_c50_p1 | -0.053 [-0.077..-0.041] (0/8 boots+, 32/32 pairs<0) | -0.004 [-0.017..+0.018] (4/8 boots+, 17/32 pairs<0) | +0.063 [+0.034..+0.072] (8/8 boots+, 0/32 pairs<0) |
| get_c50_p1_d1 | -0.081 [-0.096..-0.053] (0/8 boots+, 32/32 pairs<0) | +0.092 [+0.043..+0.128] (8/8 boots+, 1/32 pairs<0) | +0.165 [+0.129..+0.206] (8/8 boots+, 0/32 pairs<0) |

Per request, median over runs (counters of the loaded module); exits = bl/blr/br/ret; brackets = fpsimd_entries; boundary = ibtc_fpsimd_boundary; sticky = fp_sticky_set (per run); mem = fpsimd_exit_mem; declined = run_declined; ibtc misses = cold+conflict+other; insert = ibtc_insert (slot stores); fragments = translate_ok since the module was loaded (warm-ups included, the cell's server)
| cell | state | fragments | in-kernel syscalls | fragment entries | brackets | boundary | sticky | chains | exit bl/blr/br/ret | exit svc/mem/unsup/budget | mem (bracketed) | declined | ibtc misses | insert |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | main | 276 | 2.160 | 3.1608 | 0.9999 | 0.99987 | 0 | 0.9999 | 0.0005/0.0000/0.9999/0.0005 | 2.1599/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00108 | 0.00001 |
| unix_get_c50_p1_d1 | a23 | 276 | 2.192 | 2.1924 | 0.9999 | 0.00000 | 1 | 0.0000 | 0.0005/0.0000/0.0000/0.0005 | 2.1917/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00107 | 0.00001 |
| unix_set_c50_p1_d1 | main | 297 | 2.094 | 3.0956 | 0.9999 | 0.99992 | 0 | 0.9999 | 0.0007/0.0000/0.9999/0.0004 | 2.0945/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00105 | 0.00000 |
| unix_set_c50_p1_d1 | a23 | 297 | 2.126 | 2.1273 | 1.0000 | 0.00000 | 0 | 0.0000 | 0.0007/0.0000/0.0000/0.0003 | 2.1261/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00101 | 0.00000 |
| unix_pingm_c50_p1 | main | 245 | 2.179 | 3.1804 | 0.9998 | 0.99983 | 0 | 0.9998 | 0.0006/0.0000/1.0000/0.0007 | 2.1790/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00155 | 0.00001 |
| unix_pingm_c50_p1 | a23 | 237 | 2.131 | 2.1324 | 0.9999 | 0.00000 | 0 | 0.0000 | 0.0007/0.0000/0.0002/0.0003 | 2.1311/0.0000/0.0000/0.0000 | 0.00000 | 0.00004 | 0.00135 | 0.00000 |
| get_c50_p1_d1 | main | 269 | 2.058 | 3.0598 | 0.9999 | 0.99994 | 0 | 0.9999 | 0.0013/0.0000/1.0001/0.0005 | 2.0576/0.0000/0.0000/0.0000 | 0.00000 | 0.00005 | 0.00225 | 0.00000 |
| get_c50_p1_d1 | a23 | 270 | 2.064 | 2.0661 | 1.0000 | 0.00000 | 0 | 0.0000 | 0.0012/0.0000/0.0002/0.0007 | 2.0638/0.0000/0.0000/0.0000 | 0.00000 | 0.00005 | 0.00226 | 0.00001 |

