#!/usr/bin/env python3
"""Hot-path word census of the A20 translator on the redis SET/GET request gaps.

  census.py RAWDIR OUTDIR            RAWDIR holds set.tsv, set.tsv.words, get.tsv, get.tsv.words
                                     (the output of harness/src/bin/census.rs, see run.sh)

Per request = per 100000 requests of the E1 trace (the divisor of the 2026-10-14 13:56 entry's
counts.py; it reproduces that entry's 13357.8 / 11148.8 totals once `exit_preamble` is counted).

Word classes (hot path = the words executed when a dispatch template hits its main probe):
  user_op user_synth link_write user_access fill spill helper_other budget align range window_access
  link_slot dispatch_target dispatch_target_dyn dispatch_lookup
Not on the hot path, listed so the old totals reconcile:
  exit_preamble  the reg-virt words (fill pt_regs ptr, str x9/x10/x11) at the head of a runtime exit
                 group; they sit after the template's final `br` (or are all of an SVC site), so they
                 execute on a template miss / SVC only.  The 13:56 tool counted them as fill/helper_other.
  exit_group     the exit group's payload words and branch
  dispatch_victim the template's victim probe (11 words), reached only when the main probe misses
A linked BL (99% of BL executions) skips its target move and the template: weight 0.01.

Candidates are what-if rewrites of the emitted word streams (see CANDS); a rewrite that removes or
shortens words is applied to the retranslated sequences, never to the product code.
"""
import collections
import csv
import gzip
import os
import re
import sys

N = 100000.0
RAW, OUT = sys.argv[1], sys.argv[2]
HOT = ['user_op', 'user_synth', 'link_write', 'user_access', 'fill', 'spill', 'helper_other', 'budget',
       'align', 'range', 'window_access', 'link_slot', 'dispatch_target', 'dispatch_target_dyn',
       'dispatch_lookup']
NOT_HOT = ['exit_preamble', 'exit_group', 'dispatch_victim']
SLOT_REG = {16 + 8 * i: 12 + i for i in range(6)}
SLOT_REG[192] = 18


def mn(text):
    return text.split()[0] if text else '?'


def load(t):
    pcs = {}
    with open(f'{RAW}/{t}.tsv') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            r['count'] = int(r['count'])
            pcs[r['pc']] = r
    words = collections.defaultdict(list)
    path = f'{RAW}/{t}.tsv.words'
    opener = open if os.path.exists(path) else gzip.open
    path = path if os.path.exists(path) else path + '.gz'
    with opener(path, 'rt') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            words[r['pc']].append(r)
    return pcs, words


def classify(pcs, words):
    seqs = collections.defaultdict(list)
    for pc, ws in words.items():
        r = pcs[pc]
        m = mn(r['text'])
        lastd, firstp = -1, None
        for w in ws:
            i = int(w['idx'])
            if w['kind'] == 'DispatchLookup':
                lastd = i
            if w['kind'] == 'RuntimeExitPayload' and firstp is None:
                firstp = i
        for w in ws:
            i, k, c, t = int(w['idx']), w['kind'], w['class'], w['text']
            if k.startswith('RuntimeExit'):
                cls = 'exit_group'
            elif k == 'RegVirtHelper' and firstp is not None and lastd < i < firstp:
                cls = 'exit_preamble'
            elif k == 'DispatchLookup' and c == '-':
                cls = 'dispatch_victim'
            else:
                cls = c
            if cls == 'user_synth' and m in ('bl', 'blr') and re.match(r'mov[zk] x30', t):
                cls = 'link_write'
            if cls == 'dispatch_target' and m != 'bl':
                cls = 'dispatch_target_dyn'
            wt = r['count'] / N
            if m == 'bl' and k in ('DispatchLookup', 'DispatchTarget'):
                wt *= 0.01
            seqs[pc].append(dict(pc=pc, idx=i, mn=m, orig=r['text'], kind=k, text=t, cls=cls, wt=wt,
                                 word=w['word'], x17w=int(w['x17w']), blk=w['blk']))
    return seqs


def hot(seqs):
    return sum(w['wt'] for s in seqs.values() for w in s if w['cls'] in HOT)


def hot_by_pc(seqs):
    return {pc: sum(w['wt'] for w in s if w['cls'] in HOT) for pc, s in seqs.items()}


def clone(seqs):
    return {pc: [dict(w) for w in s] for pc, s in seqs.items()}


# ---- register write sets (text based, conservative) ----
NOWRITE = set('str strb strh sttr sttrb sttrh stp stur cbz cbnz tbz tbnz b bl br blr ret cmp cmn tst ccmp ccmn '
              'nop dmb isb dsb prfm svc'.split())
CONS = set('ldadd ldaddal ldadda ldaddl swp swpal swpl swpa cas casal casa casl ld1 st1 ldclr ldset ldeor ldumax '
           'stadd staddl ldaddb ldaddh'.split())


def written(text):
    m = text.split()[0]
    regs = [int(x) for x in re.findall(r'\b[xw](\d+)\b', text)]
    if m in NOWRITE or m.startswith('b.'):
        return []
    if m in CONS:
        return regs
    return regs[:1]


MOVRE = re.compile(r'^(movz|movk) (x\d+), #(\d+)(?:, lsl #(\d+))?$')


def blocks_of(seqs):
    byblk = collections.defaultdict(list)
    for pc, s in seqs.items():
        byblk[s[0]['blk']].append(pc)
    for pl in byblk.values():
        pl.sort(key=lambda p: int(p, 16))
    return byblk


# ================= candidates =================
def drop_zero_halfwords(seq):
    out, i = [], 0
    while i < len(seq):
        w = seq[i]
        m = MOVRE.match(w['text'])
        if m and w['kind'] in ('UserSynthetic', 'DispatchTarget') and m.group(1) == 'movz' and (m.group(4) or '0') == '48':
            reg, grp, j = m.group(2), [w], i + 1
            while j < len(seq):
                mm = MOVRE.match(seq[j]['text'])
                if mm and mm.group(1) == 'movk' and mm.group(2) == reg and seq[j]['kind'] == w['kind']:
                    grp.append(seq[j])
                    j += 1
                else:
                    break
            nz = [g for g in grp if int(MOVRE.match(g['text']).group(3)) != 0] or [grp[-1]]
            out += nz
            i = j
        else:
            out.append(w)
            i += 1
    return out


def c1(seqs, ctx):
    """ADRP/link write/BL target as minimal movz/movk chains (one word per nonzero halfword); an ADRP into a
    stack-backed register builds in the scratch and spills once."""
    out = {}
    for pc, s in seqs.items():
        if s and s[0]['mn'] == 'adrp' and any(w['cls'] in ('fill', 'spill') for w in s):
            s = [w for w in s if w['kind'] == 'UserSynthetic'] + [[w for w in s if w['cls'] == 'spill'][-1]]
        out[pc] = drop_zero_halfwords(s)
    return out


def c2(seqs, ctx):
    """SP-based LDP (imm % 16 == 0 or post-index): both accesses in one 16-byte granule of an aligned SP, so the
    first LDTR may load straight into its final register."""
    out = {}
    for pc, s in seqs.items():
        if s and s[0]['mn'] == 'ldp' and '[sp' in s[0]['orig']:
            m = re.search(r'\[sp(?:, #(-?\d+))?\]', s[0]['orig'])
            imm = int(m.group(1) or 0) if m else 0
            if imm % 16 == 0 or re.search(r'\[sp\], #', s[0]['orig']):
                s = [w for w in s if not (w['cls'] == 'user_op' and re.match(r'mov x\d+, x1[2-5]$', w['text']))]
        out[pc] = s
    return out


def c3(seqs, ctx):
    """Redundant fill: `ldr xS, [sp, slot]` when xS still holds the slot (block-local, entries are block starts)."""
    out = {}
    for b, pl in blocks_of(seqs).items():
        held = {}
        for pc in pl:
            o = []
            for w in seqs[pc]:
                if w['cls'] in NOT_HOT:
                    o.append(w)
                    continue
                mm = re.match(r'(ldr|str) x(\d+), \[sp, #(\d+)\]$', w['text'])
                if mm and w['kind'] == 'RegVirtHelper' and (16 <= int(mm.group(3)) < 64 or int(mm.group(3)) == 192):
                    op, reg, slot = mm.group(1), int(mm.group(2)), int(mm.group(3))
                    if op == 'ldr':
                        if held.get(reg) == slot:
                            continue
                        held[reg] = slot
                    else:
                        for y in list(held):
                            if held[y] == slot and y != reg:
                                del held[y]
                        held[reg] = slot
                else:
                    for y in written(w['text']):
                        held.pop(y, None)
                o.append(w)
            out[pc] = o
    return out


def c4(seqs, ctx):
    """User SP aligned for the whole run (run-entry condition + guard on SP writes): no SP alignment checks."""
    out = {}
    for pc, s in seqs.items():
        o, i = [], 0
        while i < len(s):
            if (s[i]['kind'] == 'AlignCheck' and re.match(r'and x\d+, x17, #0xf$', s[i]['text'])
                    and i + 1 < len(s) and s[i + 1]['kind'] == 'AlignCheck' and s[i + 1]['text'].startswith('cbnz')):
                i += 2
                continue
            o.append(s[i])
            i += 1
        out[pc] = o
    return out


def c5(seqs, ctx):
    """Budget unit only on back-edges that lie on an intra-fragment CFG cycle (bud_red from census.rs)."""
    out = {}
    for pc, s in seqs.items():
        if int(ctx['pcs'][pc]['bud_red']) > 0:
            s = [w for w in s if w['kind'] != 'BudgetCheck']
        out[pc] = s
    return out


def c6(seqs, ctx):
    """RET dispatches on x30 directly (second template shape): no `mov x13, x30`."""
    return {pc: ([w for w in s if w['kind'] != 'DispatchTarget'] if s and s[0]['mn'] == 'ret' else s)
            for pc, s in seqs.items()}


def c7(seqs, ctx):
    """No budget unit on a direct BL whose target is above the site (user pc strictly increases)."""
    out = {}
    for pc, s in seqs.items():
        if s and s[0]['mn'] == 'bl' and int(s[0]['orig'].split('#')[1]) > 0:
            s = [w for w in s if w['kind'] != 'BudgetCheck']
        out[pc] = s
    return out


def c8(seqs, ctx):
    """Synthesised 64-bit constants (ADRP result, BL link write, BL target) as one pc-relative literal load
    from a fragment-local pool (applied after C1: chains of nonzero halfwords become one word)."""
    out = {}
    for pc, s in seqs.items():
        o, i = [], 0
        while i < len(s):
            m = MOVRE.match(s[i]['text'])
            if m and s[i]['kind'] in ('UserSynthetic', 'DispatchTarget'):
                j = i + 1
                while j < len(s) and MOVRE.match(s[j]['text']) and MOVRE.match(s[j]['text']).group(1) == 'movk' \
                        and MOVRE.match(s[j]['text']).group(2) == m.group(2) and s[j]['kind'] == s[i]['kind']:
                    j += 1
                o.append(s[i])
                i = j
            else:
                o.append(s[i])
                i += 1
        out[pc] = o
    return out


def c10(seqs, ctx):
    """Window accesses: no `mov xS, xN` copy of a direct-mapped base, and a 3-word crossing check."""
    out = {}
    for pc, s in seqs.items():
        o = []
        for w in s:
            if w['cls'] == 'helper_other' and re.match(r'mov x1[2-5], x(\d|1\d|2\d)$', w['text']) \
                    and w['mn'] in ('ldadd', 'ldaddal', 'swp', 'swpal', 'cas', 'casal', 'ldclr', 'ldset', 'ldeor', 'ldumax') \
                    and not re.match(r'mov x1[2-5], x1[2-8]$', w['text']):
                continue
            o.append(w)
        for k in range(len(o) - 3):
            if [o[k + q]['kind'] for q in range(4)] == ['AlignCheck'] * 4 and o[k + 1]['text'].startswith('add') \
                    and o[k + 3]['text'].startswith('cbnz'):
                del o[k + 2]
                break
        out[pc] = o
    return out


CANDS = [
    # id, name, fn, risk (1..5), verifier impact, in the combined stack
    ('C1', 'minimal movz/movk chains; ADRP into a stack-backed register: build in scratch, one spill', c1, 1, 'none', True),
    ('C2', 'SP-based LDP loads straight into the destination register', c2, 2, 'none', True),
    ('C3', 'redundant fill peephole (block-local)', c3, 2, 'none', True),
    ('C4', 'user SP aligned for the whole run: run-entry condition + SP-write guard, no SP checks', c4, 3, 'none (verifier never checked SP alignment)', True),
    ('C5', 'budget unit only on back-edges on an intra-fragment CFG cycle', c5, 3, 'rule 6 rewritten (cycle check over the body words)', True),
    ('C6', 'RET dispatches on x30 (second template shape)', c6, 3, 'rule 4: second byte-exact template shape; miss payload exception', True),
    ('C7', 'no budget unit on a forward direct BL', c7, 4, 'new rule trusting a translator-supplied site pc', True),
    ('C10', 'window access: no copy of a direct base, 3-word crossing check', c10, 1, 'none', True),
    ('C8', 'synthesised constants as one pool literal load (after C1)', c8, 5, 'new rule: pc-relative literal load from a fragment pool', False),
]


def group(m, text):
    if m in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh', 'ldur', 'ldurb', 'ldurh', 'ldursw'):
        return 'load'
    if m in ('str', 'strb', 'strh', 'stur', 'sturb', 'sturh'):
        return 'store'
    if m in ('ldp', 'stp', 'adrp', 'adr', 'bl', 'blr', 'br', 'ret', 'svc', 'b'):
        return m
    if m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        return 'cond_branch'
    if re.match(r'(ldadd|ldclr|ldset|ldeor|swp|cas|stadd|ldumax|ldar|stlr|ldapr|ldax|stlx)', m):
        return 'atomic_acqrel'
    if m in ('mov', 'movz', 'movk', 'movn', 'mvn'):
        return 'mov'
    if m in ('add', 'sub', 'adds', 'subs', 'cmp', 'cmn', 'neg'):
        return 'add_sub'
    if m in ('and', 'orr', 'eor', 'tst', 'bic', 'ands', 'orn', 'eon'):
        return 'logic'
    if m in ('lsl', 'lsr', 'asr', 'ubfx', 'sbfx', 'ubfiz', 'sbfiz', 'bfi', 'bfxil', 'ror', 'extr', 'sxtw', 'uxtb',
             'uxth', 'sxtb', 'sxth', 'ubfm', 'sbfm', 'bfm', 'bfc'):
        return 'shift_bitfield'
    if m in ('csel', 'cset', 'csinc', 'csinv', 'csetm', 'csneg', 'ccmp', 'ccmn', 'cinc', 'cneg'):
        return 'cond_select'
    if m in ('mul', 'madd', 'msub', 'smull', 'umulh', 'umull', 'udiv', 'sdiv', 'smulh', 'mneg', 'umaddl', 'smaddl'):
        return 'mul_div'
    if m in ('nop', 'prfm', 'dmb', 'isb', 'dsb', 'bti', 'mrs'):
        return 'nop_hint_sys'
    return 'other_alu_simd'


def mem_form(text):
    m = re.search(r'\[(.*)\](!?)(, #?(-?\d+))?$', text)
    if not m:
        return None
    inner, bang, post = m.group(1), m.group(2), m.group(3)
    isp = inner.split(',')[0].strip() == 'sp'
    if post:
        f = 'post'
    elif bang:
        f = 'pre'
    elif ',' in inner:
        off = inner.split(',', 1)[1].strip()
        if off.startswith('#'):
            f = 'imm_simm9' if -256 <= int(off[1:]) <= 255 else 'imm_wide'
        else:
            f = 'reg'
    else:
        f = 'base'
    return ('sp_' if isp else 'x_') + f


def w_csv(path, header, rows):
    with open(path, 'w', newline='') as f:
        wr = csv.writer(f, lineterminator='\n')
        wr.writerow(header)
        for r in rows:
            wr.writerow(r)


def rnd(x):
    return round(x, 3)


os.makedirs(OUT, exist_ok=True)
T = {}
for t in ('set', 'get'):
    pcs, words = load(t)
    T[t] = (pcs, classify(pcs, words), words)

# ---- class table ----
rows = []
for t, (pcs, seqs, _) in T.items():
    tot = collections.Counter()
    for s in seqs.values():
        for w in s:
            tot[w['cls']] += w['wt']
    h = sum(tot[c] for c in HOT)
    orig = sum(r['count'] for r in pcs.values()) / N
    for c in HOT + NOT_HOT:
        rows.append([t, c, int(c in HOT), rnd(tot[c]), rnd(100 * tot[c] / h) if c in HOT else ''])
    rows.append([t, 'TOTAL_HOT', 1, rnd(h), 100.0])
    rows.append([t, 'OLD_TOOL_TOTAL (hot + exit_preamble)', 0, rnd(h + tot['exit_preamble']), ''])
    rows.append([t, 'ORIGINAL_INSNS', 0, rnd(orig), ''])
w_csv(f'{OUT}/class-table.csv', ['test', 'class', 'hot', 'words_per_req', 'share_of_hot_pct'], rows)

# ---- group / mnemonic tables ----
rows, mrows = [], []
for t, (pcs, seqs, _) in T.items():
    cnt, cw = collections.Counter(), collections.defaultdict(collections.Counter)
    mcnt, mw = collections.Counter(), collections.Counter()
    for pc, r in pcs.items():
        g = group(mn(r['text']), r['text'])
        cnt[g] += r['count'] / N
        mcnt[mn(r['text'])] += r['count'] / N
    for s in seqs.values():
        for w in s:
            if w['cls'] in HOT:
                cw[group(w['mn'], w['orig'])][w['cls']] += w['wt']
                mw[w['mn']] += w['wt']
    for g in sorted(cw, key=lambda g: -sum(cw[g].values())):
        tw = sum(cw[g].values())
        for c in HOT:
            if cw[g][c]:
                rows.append([t, g, rnd(cnt[g]), rnd(tw), rnd(tw / cnt[g]), c, rnd(cw[g][c])])
    for m in sorted(mw, key=lambda m: -mw[m]):
        mrows.append([t, m, rnd(mcnt[m]), rnd(mw[m]), rnd(mw[m] / mcnt[m]) if mcnt[m] else ''])
w_csv(f'{OUT}/group-table.csv', ['test', 'group', 'exec_per_req', 'group_hot_words_per_req', 'words_per_exec', 'class', 'class_words_per_req'], rows)
w_csv(f'{OUT}/mnemonic-table.csv', ['test', 'mnemonic', 'exec_per_req', 'hot_words_per_req', 'words_per_exec'], mrows)

# ---- helper_other, fill/spill, memory forms, budget, sp ----
hrows, frows, fmrows, mrows, brows, srows = [], [], [], [], [], []
for t, (pcs, seqs, words) in T.items():
    h = collections.Counter()
    for s in seqs.values():
        for w in s:
            if w['cls'] == 'helper_other':
                tx = w['text']
                if re.match(r'add x\d+, x\d+, x\d+, (uxtx|sxtw|uxtw)', tx):
                    k = 'address: add base + index register'
                elif re.match(r'(add|sub) x\d+, x\d+, #', tx):
                    k = 'address: add/sub base +- wide immediate (offset out of simm9, or pre/post-index base)'
                elif re.match(r'mov x\d+, x\d+$', tx):
                    k = 'mov base into scratch (window access)'
                else:
                    k = 'other: ' + re.sub(r'#-?\d+|x\d+', '_', tx)
                h[k] += w['wt']
    old = sum(w['wt'] for s in seqs.values() for w in s if w['cls'] == 'exit_preamble' and w['text'].startswith('str'))
    oldf = sum(w['wt'] for s in seqs.values() for w in s if w['cls'] == 'exit_preamble' and w['text'].startswith('ldr'))
    hrows.append([t, 'exit-group preamble `str x9/x10/x11, [x12, #72/80/88]` (helper_other in the 13:56 tool; not hot)', rnd(old), 0])
    hrows.append([t, 'exit-group preamble `ldr x12, [sp, #176]` (fill in the 13:56 tool; not hot)', rnd(oldf), 0])
    for k, v in sorted(h.items(), key=lambda x: -x[1]):
        hrows.append([t, k, rnd(v), 1])
    # fill/spill by user register and by group
    fs, fg = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    for s in seqs.values():
        for w in s:
            if w['cls'] in ('fill', 'spill'):
                off = int(re.search(r'#(\d+)', w['text']).group(1))
                fs[SLOT_REG[off]][w['cls']] += w['wt']
                fg[group(w['mn'], w['orig'])][w['cls']] += w['wt']
    ref = collections.Counter()
    for pc, r in pcs.items():
        for x in set(re.findall(r'\b[xw](\d+)\b', r['text'])):
            ref[int(x)] += r['count'] / N
    for reg in range(12, 19):
        frows.append([t, 'user_reg', f'x{reg}', rnd(ref[reg]), rnd(fs[reg]['fill']), rnd(fs[reg]['spill'])])
    for g in sorted(fg, key=lambda g: -sum(fg[g].values())):
        frows.append([t, 'orig_group', g, '', rnd(fg[g]['fill']), rnd(fg[g]['spill'])])
    for reg in list(range(0, 12)) + list(range(19, 31)):
        frows.append([t, 'direct_reg_refs', f'x{reg}', rnd(ref[reg]), 0, 0])
    # memory forms
    cnt, mem = collections.Counter(), collections.defaultdict(collections.Counter)
    for pc, r in pcs.items():
        m = mn(r['text'])
        if m in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh', 'str', 'strb', 'strh', 'ldp', 'stp', 'ldur', 'stur', 'ldurh', 'ldurb', 'sturb'):
            k = ('pair' if m in ('ldp', 'stp') else ('load' if m.startswith('ld') else 'store'), mem_form(r['text']) or '?')
            cnt[k] += r['count'] / N
    for s in seqs.values():
        for w in s:
            if w['cls'] in HOT and w['mn'] in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh', 'str', 'strb', 'strh', 'ldp', 'stp', 'ldur', 'stur', 'ldurh', 'ldurb', 'sturb'):
                k = ('pair' if w['mn'] in ('ldp', 'stp') else ('load' if w['mn'].startswith('ld') else 'store'), mem_form(w['orig']) or '?')
                mem[k][w['cls']] += w['wt']
    for k in sorted(cnt, key=lambda k: -sum(mem[k].values())):
        tw = sum(mem[k].values())
        for c, v in sorted(mem[k].items(), key=lambda x: -x[1]):
            mrows.append([t, k[0], k[1], rnd(cnt[k]), rnd(tw), rnd(tw / cnt[k]), c, rnd(v)])
    # budget sites
    kinds = collections.defaultdict(lambda: [0.0, 0.0, 0.0])
    fwd = collections.Counter()
    for pc, r in pcs.items():
        nb = int(r['budget'])
        if nb == 0:
            continue
        m = mn(r['text'])
        kind = m if m in ('bl', 'blr', 'br', 'ret') else ('back-edge ' + ('b' if m == 'b' else 'cond'))
        kinds[kind][0] += r['count'] / N * nb / 2
        kinds[kind][1] += r['count'] / N * nb
        kinds[kind][2] += r['count'] / N * int(r['bud_red'])
        if m == 'bl':
            fwd['forward' if int(r['text'].split('#')[1]) > 0 else 'backward'] += r['count'] / N
    for k, v in sorted(kinds.items(), key=lambda x: -x[1][1]):
        brows.append([t, k, rnd(v[0]), rnd(v[1]), rnd(v[2])])
    brows.append([t, 'bl forward (target above the site) units', rnd(fwd['forward']), rnd(2 * fwd['forward']), ''])
    brows.append([t, 'bl backward units', rnd(fwd['backward']), rnd(2 * fwd['backward']), ''])
    # sp
    sp = sum(int(r['sp_check']) * r['count'] for r in pcs.values()) / N
    srows += [[t, 'sp_check_words_per_req (after A20 dedup)', rnd(sp)],
              [t, 'sp_check_groups_per_req', rnd(sp / 2)],
              [t, 'saved_by_cross_block_dataflow (all blocks with predecessors, greatest fixpoint)', rnd(sum(int(r['sav_a']) * r['count'] for r in pcs.values()) / N)],
              [t, 'saved_by_unique_predecessor_only', rnd(sum(int(r['sav_b']) * r['count'] for r in pcs.values()) / N)],
              [t, 'saved_by_sp_invariant (C4)', rnd(sp)]]
    wr = collections.Counter()
    for s in seqs.values():
        for w in s:
            if w['x17w']:
                wr['adjust_by_16k' if w['x17w'] == 1 else 'other_write'] += w['wt']
    srows += [[t, 'x17_writes_per_req add/sub #16k (pair writeback, sub sp)', rnd(wr['adjust_by_16k'])],
              [t, 'x17_writes_per_req other (would need a guard under C4)', rnd(wr['other_write'])]]
w_csv(f'{OUT}/helper-other.csv', ['test', 'pattern', 'words_per_req', 'hot'], hrows)
w_csv(f'{OUT}/fill-spill.csv', ['test', 'by', 'key', 'refs_per_req', 'fill_words_per_req', 'spill_words_per_req'], frows)
w_csv(f'{OUT}/memory-forms.csv', ['test', 'access', 'form', 'exec_per_req', 'form_hot_words_per_req', 'words_per_exec', 'class', 'class_words_per_req'], mrows)
w_csv(f'{OUT}/budget-sites.csv', ['test', 'site_kind', 'units_per_req', 'words_per_req', 'words_per_req_off_any_cfg_cycle'], brows)
w_csv(f'{OUT}/sp-check.csv', ['test', 'metric', 'value'], srows)

# ---- candidates ----
crow, perpc_sav = [], {}
for t, (pcs, seqs, _) in T.items():
    ctx = {'pcs': pcs}
    base = hot(seqs)
    cur, prev = clone(seqs), base
    inc = {}
    for cid, name, fn, risk, ver, stack in CANDS:
        if stack:
            cur = fn(cur, ctx)
            inc[cid] = prev - hot(cur)
            prev = hot(cur)
    c1_only = c1(clone(seqs), ctx)
    cur8 = c8(clone(c1_only), ctx)
    inc['C8'] = hot(c1_only) - hot(cur8)
    stack_total = base - prev
    for cid, name, fn, risk, ver, stack in CANDS:
        # C8 is measured on top of C1 (its chains are the minimal ones)
        alone = fn(clone(seqs), ctx) if cid != 'C8' else cur8
        alone_sav = base - hot(alone) if cid != 'C8' else inc['C8']
        crow.append([t, cid, name, rnd(alone_sav), rnd(inc[cid]), rnd(100 * alone_sav / base), risk, ver, rnd(alone_sav / risk)])
        hb, ha = (hot_by_pc(seqs), hot_by_pc(alone)) if cid != 'C8' else (hot_by_pc(c1_only), hot_by_pc(cur8))
        for pc in seqs:
            perpc_sav.setdefault((t, pc), {})[cid] = hb[pc] - ha[pc]
    crow.append([t, 'STACK', 'C1..C7,C10 applied in order (C8 not included)', rnd(stack_total), rnd(stack_total), rnd(100 * stack_total / base), '', '', ''])
    crow.append([t, 'BASE', 'hot words per request on main (A20)', rnd(base), '', '', '', '', ''])
    crow.append([t, 'AFTER_STACK', 'hot words per request after the stack', rnd(prev), '', '', '', '', ''])
    tot = collections.Counter()
    for s in cur.values():
        for w in s:
            tot[w['cls']] += w['wt']
    for c in HOT:
        crow.append([t, 'AFTER_STACK_CLASS', c, rnd(tot[c]), '', '', '', '', ''])
w_csv(f'{OUT}/candidates.csv', ['test', 'id', 'name', 'standalone_words_per_req', 'incremental_words_per_req_in_stack_order',
                                'standalone_pct_of_hot', 'risk_1_to_5', 'verifier_impact', 'standalone_words_per_risk'], crow)

# ---- top 30 per test ----
trows = []
txt = []
for t, (pcs, seqs, _) in T.items():
    hb = hot_by_pc(seqs)
    top = sorted(hb, key=lambda p: -hb[p])[:30]
    txt.append(f'===== {t.upper()}: 30 original instructions with the most hot-path words per request =====')
    for rank, pc in enumerate(top, 1):
        r = pcs[pc]
        img = r['image'].split('/')[-1]
        ex = r['count'] / N
        txt.append(f"\n#{rank:<2} {img}+{r['vaddr']}  {r['text']}   exec/req={ex:.2f}  hot words/exec={hb[pc]/ex:.2f}  words/req={hb[pc]:.1f}")
        for w in seqs[pc]:
            flag = {'exit_group': 'exit', 'exit_preamble': 'exit', 'dispatch_victim': 'miss'}.get(w['cls'], w['cls'])
            note = ' (x0.01: linked BL skips it)' if w['mn'] == 'bl' and w['kind'] in ('DispatchLookup', 'DispatchTarget') and w['cls'] in HOT else ''
            txt.append(f"     {w['idx']:>2} {w['word']}  {w['text']:<34} {flag}{note}")
            trows.append([t, rank, img, r['vaddr'], r['text'], rnd(ex), rnd(hb[pc]), w['idx'], w['kind'], w['cls'], int(w['cls'] in HOT), w['word'], w['text']])
open(f'{OUT}/top30-sequences.txt', 'w').write('\n'.join(txt) + '\n')
w_csv(f'{OUT}/top30.csv', ['test', 'rank', 'image', 'vaddr', 'orig_text', 'exec_per_req', 'hot_words_per_req', 'idx', 'kind', 'class', 'hot', 'word', 'asm'], trows)

# ---- the main per-pc table ----
main = []
for t, (pcs, seqs, _) in T.items():
    for pc, r in pcs.items():
        cls = collections.Counter()
        for w in seqs[pc]:
            cls[w['cls']] += 1
        ex = r['count'] / N
        hw = sum(cls[c] for c in HOT)
        wcls = collections.Counter()
        for w in seqs[pc]:
            wcls[w['cls']] += w['wt']
        sav = perpc_sav[(t, pc)]
        main.append([t, r['image'], r['vaddr'], pc, rnd(ex), r['word'], r['text'], mn(r['text']), group(mn(r['text']), r['text']),
                     rnd(sum(wcls[c] for c in HOT))] + [rnd(wcls[c]) for c in HOT + NOT_HOT]
                    + [rnd(sav[c]) for c in ('C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C10')]
                    + [int(r['sav_a']) * r['count'] / N, int(r['sav_b']) * r['count'] / N])
w_csv(OUT + '.csv', ['test', 'image', 'vaddr', 'pc', 'exec_per_req', 'orig_word', 'orig_text', 'mnemonic', 'group', 'hot_words_per_req']
      + [f'w_{c}' for c in HOT + NOT_HOT]
      + [f'save_{c}' for c in ('C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C10')] + ['save_xblock_sp_full', 'save_xblock_sp_unique_pred'], main)
print('census.py done')
