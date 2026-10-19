# Micro boots: hot-loop unit costs (ns), median over the 3 rounds


## at22-M-k0-b1 (KPTI off)

|                                                                                             |   getppid |   raw_zn |
|:--------------------------------------------------------------------------------------------|----------:|---------:|
| off, ns per syscall                                                                         |    133.29 |   148.56 |
| on, ns per syscall                                                                          |     69.24 |    83.04 |
| off - on                                                                                    |     64.05 |    65.52 |
| svcn - on (entry/exit saved)                                                                |    100.53 |   103.4  |
| trampoline round trip into a stub (x_rep_tramp), ns per repetition                          |      8.07 |     8.09 |
| whole fragment run: trampoline + prologue + body + epilogue (x_rep_call), ns per repetition |     14.81 |    15.05 |
| whole hook body: can_run, lookup, run, stats (x_rep_run), ns per repetition                 |     40.61 |    40    |
| kjit_can_run, ns per repetition                                                             |      1.01 |     1.04 |
| kjit_lookup, ns per repetition                                                              |      4.17 |     4.7  |
| SRCU lock+unlock, ns per repetition                                                         |      9.52 |     9.54 |
| msr pan pair, ns per repetition                                                             |      7.72 |     7.81 |
| relaxed atomic add, ns per repetition                                                       |      1.96 |     2.05 |

## at22-micro-k0-b0 (KPTI off)

|                                                                                             |   getppid |   raw_zn |
|:--------------------------------------------------------------------------------------------|----------:|---------:|
| off, ns per syscall                                                                         |    132.52 |   148.56 |
| on, ns per syscall                                                                          |     68.12 |    83.18 |
| off - on                                                                                    |     64.4  |    65.38 |
| svcn - on (entry/exit saved)                                                                |    101.02 |   103.68 |
| trampoline round trip into a stub (x_rep_tramp), ns per repetition                          |      8.02 |     8.04 |
| whole fragment run: trampoline + prologue + body + epilogue (x_rep_call), ns per repetition |     14.78 |    14.86 |
| whole hook body: can_run, lookup, run, stats (x_rep_run), ns per repetition                 |     41.62 |    41.42 |
| kjit_can_run, ns per repetition                                                             |      1    |     1.03 |
| kjit_lookup, ns per repetition                                                              |      4.09 |     4.67 |
| SRCU lock+unlock, ns per repetition                                                         |      9.05 |     9.06 |
| msr pan pair, ns per repetition                                                             |      7.69 |     7.73 |
| relaxed atomic add, ns per repetition                                                       |      1.96 |     2.03 |

## entry_cost (ns per outer iteration)

|                                      |   off |    on |
|:-------------------------------------|------:|------:|
| ('at22-M-k0-b1', 'fp_calls1')        | 135   | 160.9 |
| ('at22-M-k0-b1', 'fp_calls128')      | 546.9 | 573.7 |
| ('at22-M-k0-b1', 'fp_calls16')       | 183.5 | 210.6 |
| ('at22-M-k0-b1', 'gpr_calls1')       | 136.2 |  67.1 |
| ('at22-M-k0-b1', 'gpr_calls128')     | 263.7 | 190.2 |
| ('at22-M-k0-b1', 'gpr_calls16')      | 146.7 |  73.7 |
| ('at22-micro-k0-b0', 'fp_calls1')    | 147.3 | 156.9 |
| ('at22-micro-k0-b0', 'fp_calls128')  | 550.9 | 563.1 |
| ('at22-micro-k0-b0', 'fp_calls16')   | 196.7 | 201.1 |
| ('at22-micro-k0-b0', 'gpr_calls1')   | 136.1 |  69.4 |
| ('at22-micro-k0-b0', 'gpr_calls128') | 271.2 | 192.5 |
| ('at22-micro-k0-b0', 'gpr_calls16')  | 164.4 |  74.2 |

## wake cost (pipe ping-pong, us)

|                                 |   sleeper_us |   writer_us |
|:--------------------------------|-------------:|------------:|
| ('at22-M-k0-b1', 'local')       |         0.97 |        6.44 |
| ('at22-M-k0-b1', 'nowrite')     |       nan    |        5.68 |
| ('at22-M-k0-b1', 'remote')      |         8.78 |       14.35 |
| ('at22-M-k0-b1', 'spin')        |       nan    |        6.7  |
| ('at22-micro-k0-b0', 'local')   |         0.98 |        6.51 |
| ('at22-micro-k0-b0', 'nowrite') |       nan    |        5.67 |
| ('at22-micro-k0-b0', 'remote')  |         8.52 |       13.34 |
| ('at22-micro-k0-b0', 'spin')    |       nan    |        6.56 |