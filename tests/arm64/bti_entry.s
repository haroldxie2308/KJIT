// A7d BTI fixture. BTI-built code (Debian's redis, static glibc) starts every
// function that can be reached indirectly with `bti c`, jump-table targets with
// `bti j`, and both with `bti jc`. Executed in sequence, BTI is a NOP, and
// translation rephrases it to one: the fragment never contains a BTI. Cases: a
// hot SVC loop whose body calls out through `blr`/`bl` (runtime exits), each
// callee translated at its own `bti c` entry (the K3 exit-target case), a
// jump-table target at `bti j`, a loop whose head is a `bti j` (back-edge
// target), and `bti jc`. Pointer authentication stays outside the subset:
// `paciasp` at an entry and `autiasp` before a `ret` take the Unsupported exit.
//
//   make harness-test-asm ASM=tests/arm64/bti_entry.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); everything else (including SP) = 0. All addresses derive from x12.

.text
.global bti_entry
bti_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

// A function entry with its landing pad; the hot loop's head is a jump target
// too (`bti j`), so the budget back-edge lands on the rephrased NOP.
    bti c
    movz x0, #6
    movz x1, #0
    movz x8, #172
.Lloop:
    bti j
    add x1, x1, #3
    svc #0
    subs x0, x0, #1
    b.ne .Lloop
    bti
    str x1, [x12, #16]
    adr x9, callee_c
    blr x9

// Translated at its own entry: the entry word is `bti c`.
.global callee_c_mark
callee_c_mark:
    svc #0
callee_c:
    bti c
    movz x2, #4
    movz x8, #64
.Lcallee_loop:
    add x3, x3, x2
    svc #0
    subs x2, x2, #1
    cbnz x2, .Lcallee_loop
    str x3, [x12, #24]
    bl callee_jc

// A jump-table dispatch: the target is a `bti j` block, reached through `br`.
.global jump_table_mark
jump_table_mark:
    svc #0
    bti c
    movz x4, #1
    adr x10, .Ltable
    add x10, x10, x4, lsl #3
    br x10
.Ltable:
    bti j
    b .Lcase0
    bti j
    b .Lcase1
.Lcase0:
    movz x5, #0xa0
    ret
.Lcase1:
    movz x5, #0xa1
    ret

// A jump-table target translated at its own `bti j` entry, falling into a
// second landing pad.
.global case_j_mark
case_j_mark:
    svc #0
    bti j
    movz x6, #0xb0
    bti jc
    add x6, x6, #1
    str x6, [x12, #32]
    ret

// `bti jc`: callable and a jump target.
.global callee_jc_mark
callee_jc_mark:
    svc #0
callee_jc:
    bti jc
    movz x7, #0x77
    str x7, [x12, #40]
    ret

// pac-ret code: `paciasp` as the entry word takes the Unsupported exit at the
// entry itself.
.global paciasp_entry_mark
paciasp_entry_mark:
    svc #0
    paciasp
    movz x0, #1
    ret

// `bti c` translates; `autiasp` before the return takes the Unsupported exit
// with the state of the instructions before it.
.global autiasp_ret_mark
autiasp_ret_mark:
    svc #0
    bti c
    movz x0, #2
    add x1, x0, #5
    autiasp
    ret
