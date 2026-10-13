Server CPU per request, us (sum_exec_runtime), median [Q1..Q3] over all runs of the cell
| cell | KJIT off | a17 on | a19 on |
|---|---|---|---|
| get_c1 | 17.84 [17.57..18.15] | 22.68 [22.46..23.12] | 20.59 [20.45..20.83] |
| get_c10 | 4.48 [4.45..4.54] | 5.41 [5.38..5.48] | 5.15 [5.13..5.18] |
| set_c1 | 18.20 [17.89..18.45] | 23.60 [23.30..23.99] | 21.24 [20.96..21.82] |
| set_c10 | 4.61 [4.60..4.65] | 5.66 [5.64..5.78] | 5.38 [5.36..5.44] |

Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs (boots with a positive per-boot median / boots)
| cell | a19 on - a17 on | a19 on - off | a17 on - off |
|---|---|---|---|
| get_c1 | -2.142 [-2.668..-1.828] (0/4) | +2.907 [+2.808..+3.189] (4/4) | +4.668 [+4.375..+5.146] (4/4) |
| get_c10 | -0.272 [-0.362..-0.203] (0/4) | +0.684 [+0.631..+0.713] (4/4) | +0.926 [+0.860..+0.967] (4/4) |
| set_c1 | -2.116 [-2.549..-2.032] (0/4) | +3.322 [+3.195..+3.424] (4/4) | +5.357 [+5.176..+5.542] (4/4) |
| set_c10 | -0.289 [-0.413..-0.223] (0/4) | +0.783 [+0.757..+0.833] (4/4) | +1.045 [+0.986..+1.086] (4/4) |

a17: 96 on-runs (fragment entries in 96), 96 off-runs (with fragment entries: 0)
a19: 96 on-runs (fragment entries in 96), 96 off-runs (with fragment entries: 0)
