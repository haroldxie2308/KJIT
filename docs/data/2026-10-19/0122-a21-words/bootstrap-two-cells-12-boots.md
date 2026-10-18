Cluster bootstrap, 5000 draws, seed 1; us of server CPU per request. neg boots = boots whose median difference is negative; neg triples = triples with a negative difference.

## KPTI forced on

| scope | difference | triples | median [Q1..Q3] | 95% CI | neg boots | neg triples |
|---|---|---|---|---|---|---|
| unix_get_c50_p1_d1 | a21 - main | 48 | -0.062 [-0.078..-0.048] | [-0.075..-0.053] | 12/12 | 45/48 |
| unix_get_c50_p1_d1 | a21 - off | 48 | -0.059 [-0.075..-0.018] | [-0.075..-0.031] | 11/12 | 42/48 |
| unix_get_c50_p1_d1 | main - off | 48 | +0.004 [-0.013..+0.028] | [-0.013..+0.023] | 5/12 | 21/48 |
| unix_pingm_c50_p1 | a21 - main | 48 | -0.084 [-0.097..-0.060] | [-0.090..-0.072] | 12/12 | 45/48 |
| unix_pingm_c50_p1 | a21 - off | 48 | -0.110 [-0.131..-0.084] | [-0.128..-0.089] | 12/12 | 45/48 |
| unix_pingm_c50_p1 | main - off | 48 | -0.021 [-0.057..-0.001] | [-0.047..-0.010] | 11/12 | 36/48 |
| pooled | a21 - main | 96 | -0.074 [-0.089..-0.053] | [-0.079..-0.062] | 12/12 | 90/96 |
| pooled | a21 - off | 96 | -0.079 [-0.118..-0.046] | [-0.097..-0.068] | 12/12 | 87/96 |
| pooled | main - off | 96 | -0.010 [-0.036..+0.018] | [-0.019..+0.003] | 10/12 | 57/96 |

