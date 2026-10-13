main 3 boots a18 3 boots

Server CPU per request, us (sum of se.sum_exec_runtime of the server's tasks / requests), median [Q1..Q3] over all runs
| cell | KJIT off | main on | a18 on |
|---|---|---|---|
| aofunix_set_c50_p1 | 2.352 [2.302..2.414] | 3.430 [3.372..3.475] | 3.413 [3.351..3.628] |
| aofalw_set_c50_p1 | 3.645 [3.539..3.717] | 4.693 [4.578..4.952] | 4.464 [4.374..4.513] |
| unix_set_c50_p1 | 2.215 [2.202..2.281] | 2.321 [2.285..2.351] | 2.285 [2.259..2.334] |

Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs (boots with a positive per-boot median / boots)
| cell | a18 on - main on | a18 on - off | main on - off | a18 on / off |
|---|---|---|---|---|
| aofunix_set_c50_p1 | +0.058 [-0.099..+0.276] (2/3) | +1.047 [+0.945..+1.350] (3/3) | +1.079 [+1.051..+1.103] (3/3) | 1.444 [1.393..1.593] |
| aofalw_set_c50_p1 | -0.338 [-0.492..-0.132] (0/3) | +0.735 [+0.247..+0.816] (3/3) | +1.088 [+0.984..+1.348] (3/3) | 1.204 [1.065..1.231] |
| unix_set_c50_p1 | -0.036 [-0.086..-0.010] (1/3) | +0.103 [+0.064..+0.151] (3/3) | +0.010 [-0.101..+0.055] (2/3) | 1.046 [1.029..1.071] |

Per request, KJIT-on runs, median over runs
| cell | module | hook calls | in-kernel syscalls | fragment entries | FP/SIMD entries | Unsupported exits | Mem exits | run_declined |
|---|---|---|---|---|---|---|---|---|
| aofunix_set_c50_p1 | main | 2.182 | 1.177 | 3.236 | 1.059 | 0.9994 | 0.0000 | 0.0001 |
| aofunix_set_c50_p1 | a18 | 2.182 | 2.176 | 3.237 | 1.059 | 0.0000 | 0.0000 | 0.0001 |
| aofalw_set_c50_p1 | main | 2.139 | 1.134 | 3.179 | 1.045 | 0.9994 | 0.0000 | 0.0002 |
| aofalw_set_c50_p1 | a18 | 2.140 | 2.132 | 3.180 | 1.045 | 0.0000 | 0.0000 | 0.0002 |
| unix_set_c50_p1 | main | 2.119 | 1.999 | 3.115 | 1.000 | 0.1139 | 0.0000 | 0.0001 |
| unix_set_c50_p1 | a18 | 2.141 | 2.135 | 3.136 | 1.000 | 0.0000 | 0.0000 | 0.0001 |

Stopping words of the cell (warm-ups included), word(exits/entry_stops), first boot of each module
- aofunix_set_c50_p1 main: 0xfc6c79c0(1086392/0) 0xd503203f(15/0)
- aofunix_set_c50_p1 a18: 0xd503203f(13/0)
- aofalw_set_c50_p1 main: 0xfc6c79c0(1086436/0) 0xd503203f(11/0)
- aofalw_set_c50_p1 a18: 0xd503203f(8/0)
- unix_set_c50_p1 main: 0x9e630160(117756/0) 0xd503203f(16/0)
- unix_set_c50_p1 a18: 0xd503203f(20/0)
