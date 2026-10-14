## KPTI forced on: 6 boots (1, 2, 3, 4, 5, 6)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | main | a20 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 18 | 2.129 [2.123..2.165] | 2.181 [2.159..2.264] | 2.146 [2.132..2.239] |
| unix_set_c50_p1_d1 | 18 | 2.159 [2.153..2.181] | 2.244 [2.229..2.345] | 2.206 [2.187..2.214] |
| unix_pingm_c50_p1 | 18 | 2.082 [2.059..2.114] | 2.078 [2.070..2.112] | 2.040 [2.030..2.087] |
| get_c50_p1_d1 | 18 | 3.047 [3.030..3.095] | 3.175 [3.126..3.225] | 3.108 [3.095..3.132] |
| set_c50_p1_d1 | 18 | 3.121 [3.100..3.153] | 3.398 [3.372..3.462] | 3.325 [3.305..3.385] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a20 - main | a20 - off | main - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.032 [-0.047..-0.023] (0/6 boots+, 16/18 pairs<0) | +0.022 [-0.008..+0.030] (4/6 boots+, 7/18 pairs<0) | +0.041 [+0.024..+0.067] (6/6 boots+, 1/18 pairs<0) |
| unix_set_c50_p1_d1 | -0.054 [-0.075..-0.025] (0/6 boots+, 15/18 pairs<0) | +0.042 [+0.029..+0.051] (5/6 boots+, 2/18 pairs<0) | +0.084 [+0.057..+0.111] (6/6 boots+, 1/18 pairs<0) |
| unix_pingm_c50_p1 | -0.040 [-0.057..-0.015] (0/6 boots+, 16/18 pairs<0) | -0.042 [-0.055..-0.018] (0/6 boots+, 16/18 pairs<0) | -0.002 [-0.018..+0.031] (3/6 boots+, 10/18 pairs<0) |
| get_c50_p1_d1 | -0.045 [-0.107..-0.017] (0/6 boots+, 15/18 pairs<0) | +0.045 [+0.026..+0.076] (6/6 boots+, 3/18 pairs<0) | +0.090 [+0.070..+0.154] (6/6 boots+, 0/18 pairs<0) |
| set_c50_p1_d1 | -0.086 [-0.100..-0.062] (0/6 boots+, 17/18 pairs<0) | +0.195 [+0.160..+0.229] (6/6 boots+, 0/18 pairs<0) | +0.277 [+0.242..+0.310] (6/6 boots+, 0/18 pairs<0) |

Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls (entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); freed = released_fragments; links = link slots patched / waiting (gauges, all mms)
| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | main | 276 | 0 | 256/205 | 2.186 | 3.1869 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.1858/0.0000/0.0000/0.0000 | 0.00126 | 0.000006 | 607 |
| unix_get_c50_p1_d1 | a20 | 276 | 0 | 256/205 | 2.153 | 3.1542 | 0.9999 | 0.0006/0.0000/1.0000/0.0006 | 2.1529/0.0000/0.0000/0.0000 | 0.00136 | 0.000007 | 602 |
| unix_set_c50_p1_d1 | main | 297 | 0 | 282/206 | 2.145 | 3.1458 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.1446/0.0000/0.0000/0.0000 | 0.00128 | 0.000004 | 641 |
| unix_set_c50_p1_d1 | a20 | 297 | 0 | 282/206 | 2.162 | 3.1628 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.1617/0.0000/0.0000/0.0000 | 0.00128 | 0.000004 | 636 |
| unix_pingm_c50_p1 | main | 245 | 0 | 232/190 | 2.148 | 3.1496 | 0.9999 | 0.0007/0.0000/1.0000/0.0008 | 2.1481/0.0000/0.0000/0.0000 | 0.00163 | 0.000011 | 548 |
| unix_pingm_c50_p1 | a20 | 245 | 0 | 232/190 | 2.155 | 3.1570 | 0.9999 | 0.0006/0.0000/1.0000/0.0009 | 2.1551/0.0000/0.0000/0.0000 | 0.00181 | 0.000010 | 544 |
| get_c50_p1_d1 | main | 270 | 0 | 250/204 | 2.075 | 3.0780 | 0.9999 | 0.0012/0.0000/1.0001/0.0008 | 2.0755/0.0000/0.0000/0.0000 | 0.00235 | 0.000005 | 589 |
| get_c50_p1_d1 | a20 | 274 | 0 | 255/204 | 2.091 | 3.0937 | 0.9999 | 0.0011/0.0000/1.0002/0.0010 | 2.0914/0.0000/0.0000/0.0000 | 0.00248 | 0.000009 | 599 |
| set_c50_p1_d1 | main | 296 | 0 | 282/206 | 2.061 | 3.0634 | 1.0000 | 0.0012/0.0000/1.0002/0.0010 | 2.0609/0.0000/0.0000/0.0000 | 0.00268 | 0.000008 | 640 |
| set_c50_p1_d1 | a20 | 297 | 0 | 282/206 | 2.069 | 3.0717 | 1.0000 | 0.0010/0.0000/1.0002/0.0011 | 2.0692/0.0000/0.0000/0.0000 | 0.00250 | 0.000010 | 636 |

## KPTI off: 4 boots (1, 2, 3, 4)

Server CPU per request, us (median [Q1..Q3] over runs)
| cell | triples | off | main | a20 |
|---|---|---|---|---|
| unix_get_c50_p1_d1 | 12 | 1.847 [1.831..1.863] | 1.982 [1.966..1.989] | 1.921 [1.916..1.930] |
| unix_set_c50_p1_d1 | 12 | 1.869 [1.860..1.878] | 2.234 [2.182..2.278] | 2.098 [2.069..2.140] |

Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median triple is positive; negative = the first term is cheaper)
| cell | a20 - main | a20 - off | main - off |
|---|---|---|---|
| unix_get_c50_p1_d1 | -0.059 [-0.069..-0.040] (0/4 boots+, 11/12 pairs<0) | +0.079 [+0.067..+0.090] (4/4 boots+, 0/12 pairs<0) | +0.150 [+0.102..+0.163] (4/4 boots+, 0/12 pairs<0) |
| unix_set_c50_p1_d1 | -0.110 [-0.194..-0.081] (0/4 boots+, 12/12 pairs<0) | +0.226 [+0.189..+0.263] (4/4 boots+, 0/12 pairs<0) | +0.365 [+0.298..+0.417] (4/4 boots+, 0/12 pairs<0) |

Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls (entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); freed = released_fragments; links = link slots patched / waiting (gauges, all mms)
| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | main | 276 | 0 | 256/205 | 2.084 | 3.0851 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.0841/0.0000/0.0000/0.0000 | 0.00123 | 0.000007 | 607 |
| unix_get_c50_p1_d1 | a20 | 276 | 0 | 256/205 | 2.104 | 3.1045 | 0.9999 | 0.0006/0.0000/0.9999/0.0005 | 2.1036/0.0000/0.0000/0.0000 | 0.00113 | 0.000005 | 602 |
| unix_set_c50_p1_d1 | main | 297 | 0 | 282/206 | 2.073 | 3.0746 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.0735/0.0000/0.0000/0.0000 | 0.00125 | 0.000005 | 641 |
| unix_set_c50_p1_d1 | a20 | 297 | 0 | 282/206 | 2.072 | 3.0736 | 0.9999 | 0.0007/0.0000/0.9999/0.0005 | 2.0723/0.0000/0.0000/0.0000 | 0.00125 | 0.000005 | 636 |

