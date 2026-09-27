/*
 * kjit_trace: QEMU user-mode TCG plugin for the E1 dynamic trace.
 *
 * Segments each guest thread's instruction stream at syscalls and records,
 * per gap, the syscall that started it, the syscall that ended it and its
 * dynamic instruction count. Per-instruction execution counts are folded
 * into aggregates keyed by (start nr, end nr, length bucket, instruction).
 *
 * Built against the qemu-plugin.h of the exact qemu-user it is loaded into
 * (QEMU 7.2, plugin API v1). See README.md for the output format.
 *
 * Usage: qemu-aarch64 -plugin ./libkjittrace.so,out=PATH,elide=NR:NR:... prog
 *   out    output file (required)
 *   elide  colon-separated syscall numbers that do not end a gap (required,
 *          may be empty). Used for syscalls that arm64 Linux serves from the
 *          vDSO natively but QEMU 7.2 linux-user executes as real SVCs.
 */
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_VCPUS 1024
#define MAX_NR 1024
#define N_BUCKETS 4
#define NR_CLONE 220
#define CLONE_VM_FLAG 0x100
/* Bucket b holds gaps with len <= BUCKET_LIMIT[b]; the last bucket is > 10000. */
static const uint64_t BUCKET_LIMIT[N_BUCKETS - 1] = {256, 1000, 10000};

static void __attribute__((noreturn, format(printf, 1, 2))) die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("kjit_trace: fatal: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    abort();
}

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n);
    if (!q) {
        die("out of memory (%zu bytes)", n);
    }
    return q;
}

/* ---- u64 -> u64 open-addressing map; key 0 is reserved as "empty" ---- */

typedef struct {
    uint64_t *keys;
    uint64_t *vals;
    size_t cap; /* power of two */
    size_t n;
} Map;

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static void map_grow(Map *m);

/* Returns the value slot for `key`, inserting a zero value when absent. */
static uint64_t *map_slot(Map *m, uint64_t key)
{
    if (key == 0) {
        die("map key 0 is reserved");
    }
    if ((m->n + 1) * 2 > m->cap) {
        map_grow(m);
    }
    size_t mask = m->cap - 1;
    for (size_t i = mix64(key) & mask;; i = (i + 1) & mask) {
        if (m->keys[i] == key) {
            return &m->vals[i];
        }
        if (m->keys[i] == 0) {
            m->keys[i] = key;
            m->vals[i] = 0;
            m->n++;
            return &m->vals[i];
        }
    }
}

static void map_grow(Map *m)
{
    Map bigger = {0};
    bigger.cap = m->cap ? m->cap * 2 : 1024;
    bigger.keys = calloc(bigger.cap, sizeof(uint64_t));
    bigger.vals = calloc(bigger.cap, sizeof(uint64_t));
    if (!bigger.keys || !bigger.vals) {
        die("out of memory growing map to %zu", bigger.cap);
    }
    for (size_t i = 0; i < m->cap; i++) {
        if (m->keys[i] != 0) {
            *map_slot(&bigger, m->keys[i]) = m->vals[i];
        }
    }
    free(m->keys);
    free(m->vals);
    *m = bigger;
}

/* ---- global state (guarded by `lock`) ---- */

typedef struct {
    uint64_t pc;
    uint32_t word;
    uint32_t image;
    uint64_t file_off;
} Insn;

typedef struct {
    uint64_t start, end, off;
    uint32_t image;
} Mapping;

typedef struct {
    uint32_t n;
    uint32_t *ids; /* sorted */
} Shape;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char *out_path;
/* Set at exit, and in forked children, which are not traced (see on_fork_child). */
static bool finished;
static bool forked_child;
static uint64_t forks; /* clone() without CLONE_VM: children not traced */

typedef struct {
    uint32_t vcpu;
    int32_t start_nr, end_nr;
    int64_t shape;
    uint64_t len, elided;
} Gap;

static Gap *gaps;
static size_t n_gaps, cap_gaps;

static bool elide[MAX_NR];
static uint64_t syscall_hist[MAX_NR];

static Insn *insns;
static uint32_t n_insns, cap_insns;
static Map pc_to_id;           /* pc -> id + 1 */
static uint64_t word_changes;  /* pc re-translated with a different word */

static char **images;
static uint32_t n_images;
static Mapping *mappings;
static size_t n_mappings;
static uint64_t maps_reloads;

static Map agg;                /* packed (start, end, bucket, id) -> count */
static Map shape_by_hash;      /* shape hash -> shape id + 1 */
static Shape *shapes;
static uint32_t n_shapes, cap_shapes;

/* ---- per-vCPU (= guest thread in linux-user) state ---- */

typedef struct {
    int64_t start_nr; /* -1: thread start */
    uint64_t len;     /* instructions executed in the current gap */
    uint64_t elided;  /* elided syscalls inside the current gap */
    uint64_t *cnt;    /* per-insn count in the current gap, indexed by id */
    uint32_t cap;
    uint32_t *touched; /* ids with cnt != 0 */
    uint32_t n_touched, cap_touched;
} Vcpu;

static Vcpu *vcpus[MAX_VCPUS];

/* ---- images from the host /proc/self/maps ---- */

static uint32_t intern_image(const char *path)
{
    for (uint32_t i = 0; i < n_images; i++) {
        if (strcmp(images[i], path) == 0) {
            return i;
        }
    }
    images = xrealloc(images, (n_images + 1) * sizeof(char *));
    images[n_images] = strdup(path);
    if (!images[n_images]) {
        die("out of memory");
    }
    return n_images++;
}

static void reload_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        die("cannot open /proc/self/maps");
    }
    maps_reloads++;
    n_mappings = 0;
    size_t cap = 0;
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        uint64_t start, end, off;
        char perms[8];
        int path_at = 0;
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %*s %*s %n", &start, &end,
                   perms, &off, &path_at) < 4) {
            die("unparseable /proc/self/maps line: %s", line);
        }
        char *path = line + path_at;
        path[strcspn(path, "\n")] = '\0';
        if (n_mappings == cap) {
            cap = cap ? cap * 2 : 256;
            mappings = xrealloc(mappings, cap * sizeof(Mapping));
        }
        mappings[n_mappings++] = (Mapping){
            .start = start,
            .end = end,
            .off = off,
            .image = intern_image(path[0] ? path : "[anon]"),
        };
    }
    fclose(f);
}

static const Mapping *find_mapping(uint64_t haddr)
{
    for (size_t i = 0; i < n_mappings; i++) {
        if (mappings[i].start <= haddr && haddr < mappings[i].end) {
            return &mappings[i];
        }
    }
    return NULL;
}

/* ---- instruction interning (translation time) ---- */

static uint32_t intern_insn(uint64_t pc, uint32_t word, const void *haddr)
{
    if (pc == 0) {
        die("instruction at pc 0");
    }
    uint64_t *slot = map_slot(&pc_to_id, pc);
    if (*slot != 0 && insns[*slot - 1].word == word) {
        return (uint32_t)(*slot - 1);
    }
    if (*slot != 0) {
        word_changes++;
    }
    uint32_t image;
    uint64_t file_off = 0;
    /*
     * No host pointer, or one outside every host mapping: attributed to a
     * pseudo-image named after the case so it shows up in the report's image
     * table instead of being dropped (not observed in the redis run).
     */
    if (!haddr) {
        image = intern_image("[no-haddr]");
    } else {
        const Mapping *m = find_mapping((uint64_t)(uintptr_t)haddr);
        if (!m) {
            reload_maps();
            m = find_mapping((uint64_t)(uintptr_t)haddr);
        }
        if (!m) {
            image = intern_image("[unmapped-haddr]");
        } else {
            image = m->image;
            file_off = (uint64_t)(uintptr_t)haddr - m->start + m->off;
        }
    }
    if (n_insns == UINT32_MAX) {
        die("too many distinct instructions");
    }
    if (n_insns == cap_insns) {
        cap_insns = cap_insns ? cap_insns * 2 : 65536;
        insns = xrealloc(insns, (size_t)cap_insns * sizeof(Insn));
    }
    insns[n_insns] = (Insn){.pc = pc, .word = word, .image = image, .file_off = file_off};
    *slot = (uint64_t)n_insns + 1;
    return n_insns++;
}

/* ---- gap bookkeeping ---- */

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

/* Interns the sorted set of distinct instruction ids executed in a gap. */
static uint32_t intern_shape(uint32_t *ids, uint32_t n)
{
    qsort(ids, n, sizeof(uint32_t), cmp_u32);
    uint64_t h = 0xcbf29ce484222325ULL ^ n;
    for (uint32_t i = 0; i < n; i++) {
        h = (h ^ ids[i]) * 0x100000001b3ULL;
    }
    if (h == 0) {
        h = 1;
    }
    uint64_t *slot = map_slot(&shape_by_hash, h);
    if (*slot != 0) {
        const Shape *s = &shapes[*slot - 1];
        if (s->n != n || memcmp(s->ids, ids, n * sizeof(uint32_t)) != 0) {
            die("shape hash collision (%#" PRIx64 ")", h);
        }
        return (uint32_t)(*slot - 1);
    }
    if (n_shapes == cap_shapes) {
        cap_shapes = cap_shapes ? cap_shapes * 2 : 4096;
        shapes = xrealloc(shapes, (size_t)cap_shapes * sizeof(Shape));
    }
    Shape s = {.n = n, .ids = xrealloc(NULL, (n ? n : 1) * sizeof(uint32_t))};
    memcpy(s.ids, ids, n * sizeof(uint32_t));
    shapes[n_shapes] = s;
    *slot = (uint64_t)n_shapes + 1;
    return n_shapes++;
}

static int bucket_of(uint64_t len)
{
    for (int b = 0; b < N_BUCKETS - 1; b++) {
        if (len <= BUCKET_LIMIT[b]) {
            return b;
        }
    }
    return N_BUCKETS - 1;
}

static uint64_t agg_key(int64_t start, int64_t end, int bucket, uint32_t id)
{
    /* start, end in [0, MAX_NR); +1 keeps the key non-zero. */
    return ((uint64_t)(start + 1) << 45) | ((uint64_t)(end + 1) << 34) |
           ((uint64_t)bucket << 32) | id;
}

/*
 * Ends the current gap of `v` with syscall `end_nr` (-1: gap still open at
 * thread/process exit). Caller holds `lock`. Only gaps closed by a syscall on
 * both ends contribute per-instruction aggregates and shapes; open gaps are
 * recorded by length only.
 */
static void close_gap(unsigned vcpu, Vcpu *v, int64_t end_nr)
{
    bool closed = v->start_nr >= 0 && end_nr >= 0;
    int bucket = bucket_of(v->len);
    int64_t shape = -1;
    if (closed) {
        for (uint32_t i = 0; i < v->n_touched; i++) {
            uint32_t id = v->touched[i];
            *map_slot(&agg, agg_key(v->start_nr, end_nr, bucket, id)) += v->cnt[id];
        }
        if (bucket < N_BUCKETS - 1) {
            shape = intern_shape(v->touched, v->n_touched);
        }
    }
    if (v->len > 0 || end_nr >= 0) {
        if (n_gaps == cap_gaps) {
            cap_gaps = cap_gaps ? cap_gaps * 2 : 65536;
            gaps = xrealloc(gaps, cap_gaps * sizeof(Gap));
        }
        gaps[n_gaps++] = (Gap){.vcpu = vcpu,
                               .start_nr = (int32_t)v->start_nr,
                               .end_nr = (int32_t)end_nr,
                               .shape = shape,
                               .len = v->len,
                               .elided = v->elided};
    }
    for (uint32_t i = 0; i < v->n_touched; i++) {
        v->cnt[v->touched[i]] = 0;
    }
    v->n_touched = 0;
    v->len = 0;
    v->elided = 0;
    v->start_nr = end_nr;
}

static Vcpu *vcpu_state(unsigned vcpu)
{
    if (vcpu >= MAX_VCPUS || !vcpus[vcpu]) {
        die("instruction/syscall on unknown vcpu %u", vcpu);
    }
    return vcpus[vcpu];
}

/* ---- callbacks ---- */

static void on_insn_exec(unsigned int vcpu, void *udata)
{
    Vcpu *v = vcpu_state(vcpu);
    uint32_t id = (uint32_t)(uintptr_t)udata;
    if (id >= v->cap) {
        uint32_t cap = v->cap ? v->cap : 65536;
        while (cap <= id) {
            cap *= 2;
        }
        v->cnt = xrealloc(v->cnt, (size_t)cap * sizeof(uint64_t));
        memset(v->cnt + v->cap, 0, (size_t)(cap - v->cap) * sizeof(uint64_t));
        v->cap = cap;
    }
    if (v->cnt[id]++ == 0) {
        if (v->n_touched == v->cap_touched) {
            v->cap_touched = v->cap_touched ? v->cap_touched * 2 : 4096;
            v->touched = xrealloc(v->touched, (size_t)v->cap_touched * sizeof(uint32_t));
        }
        v->touched[v->n_touched++] = id;
    }
    v->len++;
}

static void on_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        if (qemu_plugin_insn_size(insn) != 4) {
            die("instruction size %zu at %#" PRIx64, qemu_plugin_insn_size(insn),
                qemu_plugin_insn_vaddr(insn));
        }
        uint32_t word;
        memcpy(&word, qemu_plugin_insn_data(insn), 4);
        uint32_t iid = intern_insn(qemu_plugin_insn_vaddr(insn), word, qemu_plugin_insn_haddr(insn));
        qemu_plugin_register_vcpu_insn_exec_cb(insn, on_insn_exec, QEMU_PLUGIN_CB_NO_REGS,
                                               (void *)(uintptr_t)iid);
    }
    pthread_mutex_unlock(&lock);
}

static void on_syscall(qemu_plugin_id_t id, unsigned int vcpu, int64_t num, uint64_t a1,
                       uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                       uint64_t a7, uint64_t a8)
{
    if (num < 0 || num >= MAX_NR) {
        die("syscall number %" PRId64 " outside [0, %d)", num, MAX_NR);
    }
    pthread_mutex_lock(&lock);
    if (!finished) {
        Vcpu *v = vcpu_state(vcpu);
        syscall_hist[num]++;
        if (num == NR_CLONE && !(a1 & CLONE_VM_FLAG)) {
            forks++;
        }
        if (elide[num]) {
            v->elided++;
        } else {
            close_gap(vcpu, v, num);
        }
    }
    pthread_mutex_unlock(&lock);
}

static void free_vcpu(Vcpu *v)
{
    free(v->cnt);
    free(v->touched);
    free(v);
}

static void on_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu)
{
    if (vcpu >= MAX_VCPUS) {
        die("vcpu index %u >= %d", vcpu, MAX_VCPUS);
    }
    pthread_mutex_lock(&lock);
    if (vcpus[vcpu]) {
        /* Index reused without an exit callback: record the stale gap. */
        close_gap(vcpu, vcpus[vcpu], -1);
        free_vcpu(vcpus[vcpu]);
    }
    Vcpu *v = calloc(1, sizeof(Vcpu));
    if (!v) {
        die("out of memory");
    }
    v->start_nr = -1;
    vcpus[vcpu] = v;
    pthread_mutex_unlock(&lock);
}

static void on_vcpu_exit(qemu_plugin_id_t id, unsigned int vcpu)
{
    pthread_mutex_lock(&lock);
    if (!finished && vcpu < MAX_VCPUS && vcpus[vcpu]) {
        close_gap(vcpu, vcpus[vcpu], -1);
        free_vcpu(vcpus[vcpu]);
        vcpus[vcpu] = NULL;
    }
    pthread_mutex_unlock(&lock);
}

static void write_header(FILE *out)
{
    fprintf(out, "V 1\nB");
    for (int b = 0; b < N_BUCKETS - 1; b++) {
        fprintf(out, " %" PRIu64, BUCKET_LIMIT[b]);
    }
    fputs("\nX", out);
    for (int nr = 0; nr < MAX_NR; nr++) {
        if (elide[nr]) {
            fprintf(out, " %d", nr);
        }
    }
    fputc('\n', out);
}

static void on_atexit(qemu_plugin_id_t id, void *p)
{
    pthread_mutex_lock(&lock);
    if (forked_child) {
        pthread_mutex_unlock(&lock);
        return;
    }
    finished = true;
    for (unsigned c = 0; c < MAX_VCPUS; c++) {
        if (vcpus[c]) {
            close_gap(c, vcpus[c], -1);
        }
    }
    FILE *out = fopen(out_path, "w");
    if (!out) {
        die("cannot open output `%s`", out_path);
    }
    write_header(out);
    for (uint32_t i = 0; i < n_images; i++) {
        fprintf(out, "M %u %s\n", i, images[i]);
    }
    for (uint32_t i = 0; i < n_insns; i++) {
        fprintf(out, "I %u %" PRIx64 " %08x %u %" PRIx64 "\n", i, insns[i].pc, insns[i].word,
                insns[i].image, insns[i].file_off);
    }
    for (int nr = 0; nr < MAX_NR; nr++) {
        if (syscall_hist[nr]) {
            fprintf(out, "S %d %" PRIu64 "\n", nr, syscall_hist[nr]);
        }
    }
    for (size_t i = 0; i < n_gaps; i++) {
        const Gap *g = &gaps[i];
        fprintf(out, "G %u %d %d %" PRIu64 " %" PRIu64 " %" PRId64 "\n", g->vcpu, g->start_nr,
                g->end_nr, g->len, g->elided, g->shape);
    }
    for (uint32_t s = 0; s < n_shapes; s++) {
        fprintf(out, "H %u %u", s, shapes[s].n);
        for (uint32_t i = 0; i < shapes[s].n; i++) {
            fprintf(out, " %u", shapes[s].ids[i]);
        }
        fputc('\n', out);
    }
    for (size_t i = 0; i < agg.cap; i++) {
        uint64_t k = agg.keys[i];
        if (k == 0) {
            continue;
        }
        int64_t start = (int64_t)((k >> 45) & 0x7ff) - 1;
        int64_t end = (int64_t)((k >> 34) & 0x7ff) - 1;
        fprintf(out, "C %" PRId64 " %" PRId64 " %u %u %" PRIu64 "\n", start, end,
                (unsigned)((k >> 32) & 3), (uint32_t)k, agg.vals[i]);
    }
    fprintf(out, "T word_changes %" PRIu64 "\n", word_changes);
    fprintf(out, "T maps_reloads %" PRIu64 "\n", maps_reloads);
    fprintf(out, "T forks_not_traced %" PRIu64 "\n", forks);
    fprintf(out, "E\n");
    if (fclose(out) != 0) {
        die("failed to write output file `%s`", out_path);
    }
    pthread_mutex_unlock(&lock);
}

/*
 * Forked children (clone without CLONE_VM, e.g. redis' startup MADV_FREE fork
 * check) inherit this plugin's state. They are not traced: the child stops
 * recording and never writes the output file; the parent counts the fork.
 */
static void on_fork_prepare(void)
{
    pthread_mutex_lock(&lock);
}

static void on_fork_parent(void)
{
    pthread_mutex_unlock(&lock);
}

static void on_fork_child(void)
{
    forked_child = true;
    finished = true;
    pthread_mutex_unlock(&lock);
}

static void parse_elide(const char *list)
{
    const char *p = list;
    while (*p) {
        char *endp;
        long nr = strtol(p, &endp, 10);
        if (endp == p || nr < 0 || nr >= MAX_NR || (*endp != ':' && *endp != '\0')) {
            die("bad elide list `%s`", list);
        }
        elide[nr] = true;
        p = *endp == ':' ? endp + 1 : endp;
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc,
                                           char **argv)
{
    bool have_elide = false;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "out=", 4) == 0) {
            out_path = strdup(argv[i] + 4);
        } else if (strncmp(argv[i], "elide=", 6) == 0) {
            parse_elide(argv[i] + 6);
            have_elide = true;
        } else {
            die("unknown plugin argument `%s`", argv[i]);
        }
    }
    if (!out_path || !have_elide) {
        die("required plugin arguments: out=PATH,elide=NR:NR:... (elide may be empty)");
    }
    if (strcmp(info->target_name, "aarch64") != 0 || info->system_emulation) {
        die("only aarch64 linux-user is supported (got %s, system=%d)", info->target_name,
            info->system_emulation);
    }
    /* Fail at startup, not at exit, if the output path is not writable. */
    FILE *probe = fopen(out_path, "w");
    if (!probe || fclose(probe) != 0) {
        die("cannot create output `%s`", out_path);
    }
    if (pthread_atfork(on_fork_prepare, on_fork_parent, on_fork_child) != 0) {
        die("pthread_atfork failed");
    }

    qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
    qemu_plugin_register_vcpu_exit_cb(id, on_vcpu_exit);
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, on_syscall);
    qemu_plugin_register_atexit_cb(id, on_atexit, NULL);
    return 0;
}
