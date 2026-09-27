//! E1 dynamic-trace report: what runs between consecutive syscalls of a thread.
//!
//! Usage: e1-report <trace.txt> <out-dir>
//!
//! Reads the aggregate trace written by `tools/e1-trace/kjit_trace.c` (format
//! in `tools/e1-trace/README.md`) and writes `report.md` + `report.json` to
//! `<out-dir>`:
//!
//! 1. syscall histogram;
//! 2. gap-length distribution overall and per (start nr -> end nr) pair, plus
//!    the share of dynamic instructions in gaps within each length bucket;
//! 3. instruction-form histogram weighted by dynamic count over gaps within
//!    the largest bucket limit (10k), with KJIT admission per word from
//!    `admit_word` and cumulative coverage;
//! 4. the same for the hottest gap pairs.
//!
//! Only *closed* gaps (a syscall on both ends) are analysed; thread-start and
//! still-open gaps are counted and reported separately.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kjit_harness::a64_forms::{classify_words, WordForm};
use kjit_harness::report_util::{dist, json_str, Dist};
use kjit_harness::shared::trans::cfg::admit_word;

const FORMAT_VERSION: u32 = 1;
const HOT_PAIRS: usize = 5;
const TOP_FORMS: usize = 40;
const TOP_NEXT_FORMS: usize = 25;
const TOP_PAIR_FORMS: usize = 20;
const TOP_PAIRS_TABLE: usize = 30;
const EXAMPLE_WORDS: usize = 2;

// ---------------------------------------------------------------------------
// Trace file
// ---------------------------------------------------------------------------

struct Insn {
    pc: u64,
    word: u32,
    image: usize,
}

struct Gap {
    vcpu: u32,
    start: i32,
    end: i32,
    len: u64,
    elided: u64,
    shape: Option<usize>,
}

impl Gap {
    fn closed(&self) -> bool {
        self.start >= 0 && self.end >= 0
    }
}

struct Count {
    start: i32,
    end: i32,
    bucket: usize,
    id: usize,
    count: u64,
}

struct Trace {
    /// Upper bounds of the length buckets; bucket `limits.len()` is unbounded.
    limits: Vec<u64>,
    elided: BTreeSet<u32>,
    images: Vec<String>,
    insns: Vec<Insn>,
    syscalls: BTreeMap<u32, u64>,
    gaps: Vec<Gap>,
    shapes: Vec<Vec<usize>>,
    counts: Vec<Count>,
    totals: BTreeMap<String, u64>,
}

impl Trace {
    fn bucket_of(&self, len: u64) -> usize {
        self.limits
            .iter()
            .position(|&limit| len <= limit)
            .unwrap_or(self.limits.len())
    }

    /// Buckets `< short_buckets()` hold gaps within the largest limit.
    fn short_buckets(&self) -> usize {
        self.limits.len()
    }

    fn short_limit(&self) -> u64 {
        *self.limits.last().expect("limits validated non-empty")
    }
}

fn parse_num<T: std::str::FromStr>(
    tok: Option<&str>,
    what: &str,
    line_no: usize,
) -> Result<T, String> {
    let tok = tok.ok_or_else(|| format!("line {line_no}: missing {what}"))?;
    tok.parse()
        .map_err(|_| format!("line {line_no}: bad {what} `{tok}`"))
}

fn parse_hex(tok: Option<&str>, what: &str, line_no: usize) -> Result<u64, String> {
    let tok = tok.ok_or_else(|| format!("line {line_no}: missing {what}"))?;
    u64::from_str_radix(tok, 16).map_err(|_| format!("line {line_no}: bad hex {what} `{tok}`"))
}

fn parse_trace(text: &str) -> Result<Trace, String> {
    let mut trace = Trace {
        limits: Vec::new(),
        elided: BTreeSet::new(),
        images: Vec::new(),
        insns: Vec::new(),
        syscalls: BTreeMap::new(),
        gaps: Vec::new(),
        shapes: Vec::new(),
        counts: Vec::new(),
        totals: BTreeMap::new(),
    };
    let mut version = None;
    let mut saw_limits = false;
    let mut saw_elided = false;
    let mut ended = false;
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        if ended {
            return Err(format!("line {line_no}: data after end marker"));
        }
        let mut it = line.split_ascii_whitespace();
        let tag = it
            .next()
            .ok_or_else(|| format!("line {line_no}: empty line"))?;
        match tag {
            "V" => version = Some(parse_num::<u32>(it.next(), "version", line_no)?),
            "B" => {
                for tok in it.by_ref() {
                    trace
                        .limits
                        .push(parse_num(Some(tok), "bucket limit", line_no)?);
                }
                saw_limits = true;
            }
            "X" => {
                for tok in it.by_ref() {
                    trace
                        .elided
                        .insert(parse_num(Some(tok), "elided nr", line_no)?);
                }
                saw_elided = true;
            }
            "M" => {
                let id: usize = parse_num(it.next(), "image id", line_no)?;
                if id != trace.images.len() {
                    return Err(format!("line {line_no}: image id {id} out of order"));
                }
                let rest: Vec<&str> = it.by_ref().collect();
                if rest.is_empty() {
                    return Err(format!("line {line_no}: missing image path"));
                }
                trace.images.push(rest.join(" "));
            }
            "I" => {
                let id: usize = parse_num(it.next(), "insn id", line_no)?;
                if id != trace.insns.len() {
                    return Err(format!("line {line_no}: insn id {id} out of order"));
                }
                let pc = parse_hex(it.next(), "pc", line_no)?;
                let word = u32::try_from(parse_hex(it.next(), "word", line_no)?)
                    .map_err(|_| format!("line {line_no}: word does not fit u32"))?;
                let image: usize = parse_num(it.next(), "image", line_no)?;
                parse_hex(it.next(), "file offset", line_no)?;
                trace.insns.push(Insn { pc, word, image });
            }
            "S" => {
                let nr: u32 = parse_num(it.next(), "syscall nr", line_no)?;
                let n: u64 = parse_num(it.next(), "syscall count", line_no)?;
                if trace.syscalls.insert(nr, n).is_some() {
                    return Err(format!("line {line_no}: duplicate syscall nr {nr}"));
                }
            }
            "G" => {
                let vcpu = parse_num(it.next(), "vcpu", line_no)?;
                let start = parse_num(it.next(), "start nr", line_no)?;
                let end = parse_num(it.next(), "end nr", line_no)?;
                let len = parse_num(it.next(), "len", line_no)?;
                let elided = parse_num(it.next(), "elided", line_no)?;
                let shape: i64 = parse_num(it.next(), "shape", line_no)?;
                trace.gaps.push(Gap {
                    vcpu,
                    start,
                    end,
                    len,
                    elided,
                    shape: usize::try_from(shape).ok(),
                });
            }
            "H" => {
                let id: usize = parse_num(it.next(), "shape id", line_no)?;
                if id != trace.shapes.len() {
                    return Err(format!("line {line_no}: shape id {id} out of order"));
                }
                let n: usize = parse_num(it.next(), "shape size", line_no)?;
                let ids = it
                    .by_ref()
                    .map(|tok| parse_num(Some(tok), "shape insn id", line_no))
                    .collect::<Result<Vec<usize>, String>>()?;
                if ids.len() != n {
                    return Err(format!(
                        "line {line_no}: shape has {} ids, header says {n}",
                        ids.len()
                    ));
                }
                trace.shapes.push(ids);
            }
            "C" => trace.counts.push(Count {
                start: parse_num(it.next(), "start nr", line_no)?,
                end: parse_num(it.next(), "end nr", line_no)?,
                bucket: parse_num(it.next(), "bucket", line_no)?,
                id: parse_num(it.next(), "insn id", line_no)?,
                count: parse_num(it.next(), "count", line_no)?,
            }),
            "T" => {
                let key = it
                    .next()
                    .ok_or_else(|| format!("line {line_no}: missing total key"))?;
                trace
                    .totals
                    .insert(key.to_string(), parse_num(it.next(), "total", line_no)?);
            }
            "E" => ended = true,
            other => return Err(format!("line {line_no}: unknown record `{other}`")),
        }
        if let Some(extra) = it.next() {
            return Err(format!("line {line_no}: trailing field `{extra}`"));
        }
    }
    if !ended {
        return Err("trace has no end marker `E` (truncated?)".into());
    }
    if version != Some(FORMAT_VERSION) {
        return Err(format!(
            "trace format version {version:?}, expected {FORMAT_VERSION}"
        ));
    }
    if !saw_limits || trace.limits.is_empty() || !trace.limits.windows(2).all(|w| w[0] < w[1]) {
        return Err(format!("bad bucket limits {:?}", trace.limits));
    }
    if !saw_elided {
        return Err("trace has no elided-syscall record `X`".into());
    }
    validate(&trace)?;
    Ok(trace)
}

/// Cross-checks the records against each other: every reference in range,
/// shapes exactly on closed short gaps, and per-(pair, bucket) instruction
/// counts equal to the summed gap lengths.
fn validate(trace: &Trace) -> Result<(), String> {
    for (id, insn) in trace.insns.iter().enumerate() {
        if insn.image >= trace.images.len() {
            return Err(format!("insn {id} references unknown image {}", insn.image));
        }
    }
    for shape in &trace.shapes {
        if let Some(&bad) = shape.iter().find(|&&id| id >= trace.insns.len()) {
            return Err(format!("shape references unknown insn {bad}"));
        }
    }
    let mut gap_sums: BTreeMap<(i32, i32, usize), u64> = BTreeMap::new();
    for gap in &trace.gaps {
        let bucket = trace.bucket_of(gap.len);
        let want_shape = gap.closed() && bucket < trace.short_buckets();
        match gap.shape {
            Some(s) if !want_shape || s >= trace.shapes.len() => {
                return Err(format!("gap with unexpected shape {s} (len {})", gap.len));
            }
            None if want_shape => {
                return Err(format!("closed gap of len {} has no shape", gap.len));
            }
            _ => {}
        }
        if gap.closed() {
            *gap_sums.entry((gap.start, gap.end, bucket)).or_default() += gap.len;
        }
    }
    let mut count_sums: BTreeMap<(i32, i32, usize), u64> = BTreeMap::new();
    for c in &trace.counts {
        if c.id >= trace.insns.len() || c.bucket > trace.short_buckets() || c.start < 0 || c.end < 0
        {
            return Err(format!(
                "bad count record start={} end={} bucket={} id={}",
                c.start, c.end, c.bucket, c.id
            ));
        }
        *count_sums.entry((c.start, c.end, c.bucket)).or_default() += c.count;
    }
    if gap_sums != count_sums {
        let bad = gap_sums
            .iter()
            .find(|(k, v)| count_sums.get(k) != Some(v))
            .map(|(k, v)| format!("{k:?}: gaps {v}, counts {:?}", count_sums.get(k)))
            .or_else(|| {
                count_sums
                    .iter()
                    .find(|(k, _)| !gap_sums.contains_key(k))
                    .map(|(k, v)| format!("{k:?}: gaps none, counts {v}"))
            })
            .expect("maps differ");
        return Err(format!(
            "per-instruction counts disagree with gap lengths: {bad}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

fn syscall_name(nr: i32) -> &'static str {
    match nr {
        -1 => "<thread-start>",
        17 => "getcwd",
        19 => "eventfd2",
        20 => "epoll_create1",
        21 => "epoll_ctl",
        22 => "epoll_pwait",
        23 => "dup",
        24 => "dup3",
        25 => "fcntl",
        29 => "ioctl",
        34 => "mkdirat",
        35 => "unlinkat",
        38 => "renameat",
        43 => "statfs",
        44 => "fstatfs",
        46 => "ftruncate",
        48 => "faccessat",
        49 => "chdir",
        56 => "openat",
        57 => "close",
        59 => "pipe2",
        61 => "getdents64",
        62 => "lseek",
        63 => "read",
        64 => "write",
        65 => "readv",
        66 => "writev",
        67 => "pread64",
        68 => "pwrite64",
        72 => "pselect6",
        73 => "ppoll",
        78 => "readlinkat",
        79 => "newfstatat",
        80 => "fstat",
        82 => "fsync",
        83 => "fdatasync",
        93 => "exit",
        94 => "exit_group",
        96 => "set_tid_address",
        98 => "futex",
        99 => "set_robust_list",
        101 => "nanosleep",
        103 => "setitimer",
        113 => "clock_gettime",
        114 => "clock_getres",
        115 => "clock_nanosleep",
        122 => "sched_setaffinity",
        123 => "sched_getaffinity",
        124 => "sched_yield",
        129 => "kill",
        130 => "tkill",
        131 => "tgkill",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        139 => "rt_sigreturn",
        160 => "uname",
        163 => "getrlimit",
        164 => "setrlimit",
        165 => "getrusage",
        166 => "umask",
        167 => "prctl",
        168 => "getcpu",
        169 => "gettimeofday",
        172 => "getpid",
        173 => "getppid",
        174 => "getuid",
        175 => "geteuid",
        176 => "getgid",
        177 => "getegid",
        178 => "gettid",
        179 => "sysinfo",
        198 => "socket",
        199 => "socketpair",
        200 => "bind",
        201 => "listen",
        202 => "accept",
        203 => "connect",
        204 => "getsockname",
        205 => "getpeername",
        206 => "sendto",
        207 => "recvfrom",
        208 => "setsockopt",
        209 => "getsockopt",
        210 => "shutdown",
        211 => "sendmsg",
        212 => "recvmsg",
        214 => "brk",
        215 => "munmap",
        216 => "mremap",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        226 => "mprotect",
        233 => "madvise",
        242 => "accept4",
        260 => "wait4",
        261 => "prlimit64",
        278 => "getrandom",
        279 => "memfd_create",
        293 => "rseq",
        435 => "clone3",
        441 => "epoll_pwait2",
        _ => "?",
    }
}

fn nr_label(nr: i32) -> String {
    match syscall_name(nr) {
        "?" => format!("nr{nr}"),
        name if nr < 0 => name.to_string(),
        name => format!("{name}({nr})"),
    }
}

fn pair_label(start: i32, end: i32) -> String {
    format!("{} -> {}", nr_label(start), nr_label(end))
}

#[derive(Clone, PartialEq, Eq)]
enum Admit {
    Admitted,
    Unsupported,
    /// `admit_word` returned `Err`: not an instruction-intrinsic rejection.
    Error(String),
}

/// Dynamic-count breakdown of one form.
#[derive(Default)]
struct FormAgg {
    dynamic: u64,
    admitted: u64,
    unsupported: u64,
    admit_error: u64,
    pcs: BTreeSet<u64>,
    words: BTreeMap<u32, u64>,
}

struct FormTable {
    total: u64,
    admitted: u64,
    unsupported: u64,
    admit_error: u64,
    /// Ranked by dynamic count, descending.
    forms: Vec<(String, FormAgg)>,
    images: Vec<(String, u64)>,
}

struct Ctx<'a> {
    trace: &'a Trace,
    admit: Vec<Admit>,
    form_of: BTreeMap<u32, WordForm>,
}

impl Ctx<'_> {
    /// Per-insn dynamic counts over closed short gaps accepted by `pair`.
    fn per_insn(&self, pair: Option<(i32, i32)>) -> Vec<u64> {
        let mut per = vec![0u64; self.trace.insns.len()];
        for c in &self.trace.counts {
            if c.bucket >= self.trace.short_buckets() {
                continue;
            }
            if pair.is_some_and(|p| p != (c.start, c.end)) {
                continue;
            }
            per[c.id] += c.count;
        }
        per
    }

    fn form_table(&self, per: &[u64]) -> FormTable {
        let mut forms: BTreeMap<String, FormAgg> = BTreeMap::new();
        let mut images: BTreeMap<usize, u64> = BTreeMap::new();
        let (mut total, mut admitted, mut unsupported, mut admit_error) = (0, 0, 0, 0);
        for (id, &n) in per.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let insn = &self.trace.insns[id];
            let agg = forms
                .entry(self.form_of[&insn.word].form.clone())
                .or_default();
            agg.dynamic += n;
            agg.pcs.insert(insn.pc);
            *agg.words.entry(insn.word).or_default() += n;
            total += n;
            match self.admit[id] {
                Admit::Admitted => {
                    agg.admitted += n;
                    admitted += n;
                }
                Admit::Unsupported => {
                    agg.unsupported += n;
                    unsupported += n;
                }
                Admit::Error(_) => {
                    agg.admit_error += n;
                    admit_error += n;
                }
            }
            *images.entry(insn.image).or_default() += n;
        }
        let mut forms: Vec<(String, FormAgg)> = forms.into_iter().collect();
        forms.sort_by(|a, b| b.1.dynamic.cmp(&a.1.dynamic).then(a.0.cmp(&b.0)));
        let mut images: Vec<(String, u64)> = images
            .into_iter()
            .map(|(i, n)| (self.trace.images[i].clone(), n))
            .collect();
        images.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        FormTable {
            total,
            admitted,
            unsupported,
            admit_error,
            forms,
            images,
        }
    }

    fn examples(&self, agg: &FormAgg) -> Vec<(u32, &str)> {
        let mut words: Vec<(&u32, &u64)> = agg.words.iter().collect();
        words.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        words
            .into_iter()
            .take(EXAMPLE_WORDS)
            .map(|(w, _)| (*w, self.form_of[w].text.as_str()))
            .collect()
    }
}

impl Ctx<'_> {
    /// Non-admitted forms of `t`, ranked by non-admitted dynamic count.
    fn next_forms<'t>(&self, t: &'t FormTable) -> Vec<(&'t String, u64)> {
        let mut rows: Vec<(&String, u64)> = t
            .forms
            .iter()
            .map(|(f, a)| (f, a.unsupported + a.admit_error))
            .filter(|(_, n)| *n > 0)
            .collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        rows
    }

    /// Fully admitted closed short gaps (of `pair`, or all) if every word of
    /// the first `k` forms in `order` were admitted as well.
    fn gap_admission_with(
        &self,
        pair: Option<(i32, i32)>,
        order: &[(&String, u64)],
        k: usize,
    ) -> GapAdmission {
        let added: BTreeSet<&str> = order.iter().take(k).map(|(f, _)| f.as_str()).collect();
        let ok_insn: Vec<bool> = self
            .trace
            .insns
            .iter()
            .zip(&self.admit)
            .map(|(insn, a)| {
                *a == Admit::Admitted || added.contains(self.form_of[&insn.word].form.as_str())
            })
            .collect();
        let shape_ok: Vec<bool> = self
            .trace
            .shapes
            .iter()
            .map(|ids| ids.iter().all(|&id| ok_insn[id]))
            .collect();
        let mut out = GapAdmission::default();
        for gap in &self.trace.gaps {
            let Some(shape) = gap.shape else { continue };
            if pair.is_some_and(|p| p != (gap.start, gap.end)) {
                continue;
            }
            out.gaps += 1;
            out.insns += gap.len;
            if shape_ok[shape] {
                out.full_gaps += 1;
                out.full_insns += gap.len;
            }
        }
        out
    }
}

const ADD_STEPS: [usize; 7] = [0, 5, 10, 25, 50, 100, usize::MAX];

fn md_add_curve(m: &mut String, ctx: &Ctx, pair: Option<(i32, i32)>, t: &FormTable) {
    let order = ctx.next_forms(t);
    m.push_str("Gaps whose every instruction would be admitted after adding the first K \
non-admitted forms (order of the table above):\n\n| K | forms added | fully admitted gaps | % gaps | % gap insns |\n|---|---|---|---|---|\n");
    let mut last = None;
    for k in ADD_STEPS {
        let k = k.min(order.len());
        if last == Some(k) {
            continue;
        }
        last = Some(k);
        let a = ctx.gap_admission_with(pair, &order, k);
        writeln!(
            m,
            "| {} | {k} | {} of {} | {:.1} | {:.1} |",
            if k == order.len() {
                "all".to_string()
            } else {
                k.to_string()
            },
            a.full_gaps,
            a.gaps,
            pct(a.full_gaps, a.gaps),
            pct(a.full_insns, a.insns)
        )
        .unwrap();
    }
    m.push('\n');
}

#[derive(Default)]
struct GapAdmission {
    gaps: u64,
    insns: u64,
    full_gaps: u64,
    full_insns: u64,
}

struct PairStat {
    start: i32,
    end: i32,
    lens: Vec<u64>,
    total: u64,
    /// Dynamic instructions in gaps within each bucket limit (cumulative).
    within: Vec<u64>,
}

fn pair_stats(trace: &Trace, gaps: &[&Gap]) -> PairStat {
    let (start, end) = gaps.first().map_or((-1, -1), |g| (g.start, g.end));
    let mut within = vec![0u64; trace.limits.len()];
    let mut total = 0;
    for g in gaps {
        total += g.len;
        for (i, &limit) in trace.limits.iter().enumerate() {
            if g.len <= limit {
                within[i] += g.len;
            }
        }
    }
    PairStat {
        start,
        end,
        lens: gaps.iter().map(|g| g.len).collect(),
        total,
        within,
    }
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        100.0 * part as f64 / whole as f64
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn json_dist(d: &Option<Dist>) -> String {
    match d {
        None => "null".into(),
        Some(d) => format!(
            "{{\"n\":{},\"min\":{},\"median\":{},\"p90\":{},\"p99\":{},\"max\":{}}}",
            d.n, d.min, d.median, d.p90, d.p99, d.max
        ),
    }
}

fn json_pair(trace: &Trace, p: &PairStat) -> String {
    let within: Vec<String> = trace
        .limits
        .iter()
        .zip(&p.within)
        .map(|(l, n)| format!("\"{l}\":{n}"))
        .collect();
    format!(
        "{{\"start\":{},\"end\":{},\"label\":{},\"dist\":{},\"insns\":{},\"insns_within\":{{{}}}}}",
        p.start,
        p.end,
        json_str(&pair_label(p.start, p.end)),
        json_dist(&dist(p.lens.clone())),
        p.total,
        within.join(",")
    )
}

fn json_form_table(ctx: &Ctx, t: &FormTable, limit: usize) -> String {
    let mut s = format!(
        "{{\"total\":{},\"admitted\":{},\"unsupported\":{},\"admit_error\":{},\"images\":[",
        t.total, t.admitted, t.unsupported, t.admit_error
    );
    let images: Vec<String> = t
        .images
        .iter()
        .map(|(p, n)| format!("{{\"image\":{},\"insns\":{n}}}", json_str(p)))
        .collect();
    s.push_str(&images.join(","));
    s.push_str("],\"forms\":[");
    let forms: Vec<String> = t
        .forms
        .iter()
        .take(limit)
        .map(|(form, a)| {
            let ex: Vec<String> = ctx
                .examples(a)
                .into_iter()
                .map(|(w, text)| format!("{{\"word\":\"{w:08x}\",\"text\":{}}}", json_str(text)))
                .collect();
            format!(
                "{{\"form\":{},\"dynamic\":{},\"admitted\":{},\"unsupported\":{},\"admit_error\":{},\"distinct_pcs\":{},\"examples\":[{}]}}",
                json_str(form),
                a.dynamic,
                a.admitted,
                a.unsupported,
                a.admit_error,
                a.pcs.len(),
                ex.join(",")
            )
        })
        .collect();
    s.push_str(&forms.join(",\n    "));
    s.push_str("]}");
    s
}

fn admit_cell(a: &FormAgg) -> String {
    if a.admitted == a.dynamic {
        "yes".into()
    } else if a.unsupported == a.dynamic {
        "**no**".into()
    } else if a.admit_error == a.dynamic {
        "error".into()
    } else {
        format!(
            "partial ({:.0}% adm, {:.0}% unsup, {:.0}% err)",
            pct(a.admitted, a.dynamic),
            pct(a.unsupported, a.dynamic),
            pct(a.admit_error, a.dynamic)
        )
    }
}

fn md_form_table(m: &mut String, ctx: &Ctx, t: &FormTable, limit: usize) {
    writeln!(
        m,
        "Dynamic instructions: {} — admitted {:.1}%, unsupported {:.1}%, admit error {:.1}%. \
Distinct forms: {}.\n",
        t.total,
        pct(t.admitted, t.total),
        pct(t.unsupported, t.total),
        pct(t.admit_error, t.total),
        t.forms.len()
    )
    .unwrap();
    m.push_str("| # | form | dyn insns | % | cum % | admitted | distinct PCs | top words |\n|---|---|---|---|---|---|---|---|\n");
    let mut cum = 0;
    for (i, (form, a)) in t.forms.iter().take(limit).enumerate() {
        cum += a.dynamic;
        let ex: Vec<String> = ctx
            .examples(a)
            .into_iter()
            .map(|(w, text)| format!("`{w:08x}` {text}"))
            .collect();
        writeln!(
            m,
            "| {} | `{}` | {} | {:.2} | {:.1} | {} | {} | {} |",
            i + 1,
            form,
            a.dynamic,
            pct(a.dynamic, t.total),
            pct(cum, t.total),
            admit_cell(a),
            a.pcs.len(),
            ex.join("; ")
        )
        .unwrap();
    }
    m.push('\n');
}

/// Forms with non-admitted dynamic weight, ranked, with the admitted share of
/// the population if they were supported in that order.
fn md_next_forms(m: &mut String, ctx: &Ctx, t: &FormTable, limit: usize) {
    let rows = ctx.next_forms(t);
    writeln!(
        m,
        "Baseline admitted: {:.1}%. Non-admitted forms: {}.\n",
        pct(t.admitted, t.total),
        rows.len()
    )
    .unwrap();
    m.push_str("| # | form | non-admitted dyn insns | % | admitted % after adding |\n|---|---|---|---|---|\n");
    let mut cum = t.admitted;
    for (i, (form, n)) in rows.iter().take(limit).enumerate() {
        cum += n;
        writeln!(
            m,
            "| {} | `{}` | {} | {:.2} | {:.1} |",
            i + 1,
            form,
            n,
            pct(*n, t.total),
            pct(cum, t.total)
        )
        .unwrap();
    }
    m.push('\n');
}

fn md_images(m: &mut String, t: &FormTable) {
    m.push_str("| image | dyn insns | % |\n|---|---|---|\n");
    for (image, n) in &t.images {
        writeln!(m, "| `{image}` | {n} | {:.1} |", pct(*n, t.total)).unwrap();
    }
    m.push('\n');
}

fn md_pair_row(m: &mut String, label: &str, p: &PairStat) {
    let within: Vec<String> = p
        .within
        .iter()
        .map(|n| format!("{:.1}", pct(*n, p.total)))
        .collect();
    match dist(p.lens.clone()) {
        None => writeln!(m, "| {label} | 0 | - | - | - | - | - | 0 | - |").unwrap(),
        Some(d) => writeln!(
            m,
            "| {label} | {} | {} | {} | {} | {} | {} | {} | {} |",
            d.n,
            d.min,
            d.median,
            d.p90,
            d.p99,
            d.max,
            p.total,
            within.join(" / ")
        )
        .unwrap(),
    }
}

fn run(trace_path: &Path, out_dir: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(trace_path)
        .map_err(|err| format!("failed to read {}: {err}", trace_path.display()))?;
    let trace = parse_trace(&text)?;
    drop(text);

    // Admission and forms for every traced instruction.
    let mut admit_errors: BTreeMap<String, usize> = BTreeMap::new();
    let admit: Vec<Admit> = trace
        .insns
        .iter()
        .map(|insn| match admit_word(insn.word, insn.pc) {
            Ok(Ok(_)) => Admit::Admitted,
            Ok(Err(_)) => Admit::Unsupported,
            Err(err) => {
                let msg = err.to_string();
                *admit_errors.entry(msg.clone()).or_default() += 1;
                Admit::Error(msg)
            }
        })
        .collect();
    let words: Vec<u32> = trace
        .insns
        .iter()
        .map(|i| i.word)
        .collect::<BTreeSet<u32>>()
        .into_iter()
        .collect();
    let form_of = classify_words(&words)?;
    let ctx = Ctx {
        trace: &trace,
        admit,
        form_of,
    };

    // Gap populations.
    let closed: Vec<&Gap> = trace.gaps.iter().filter(|g| g.closed()).collect();
    let thread_start: Vec<&Gap> = trace
        .gaps
        .iter()
        .filter(|g| g.start < 0 && g.end >= 0)
        .collect();
    let open: Vec<&Gap> = trace.gaps.iter().filter(|g| g.end < 0).collect();
    let sum = |gs: &[&Gap]| gs.iter().map(|g| g.len).sum::<u64>();
    let overall = pair_stats(&trace, &closed);

    let mut by_pair: BTreeMap<(i32, i32), Vec<&Gap>> = BTreeMap::new();
    for g in &closed {
        by_pair.entry((g.start, g.end)).or_default().push(g);
    }
    let mut pairs: Vec<PairStat> = by_pair.values().map(|gs| pair_stats(&trace, gs)).collect();
    pairs.sort_by(|a, b| {
        b.lens
            .len()
            .cmp(&a.lens.len())
            .then((a.start, a.end).cmp(&(b.start, b.end)))
    });

    let short_idx = trace.limits.len() - 1;
    let mut hot: Vec<&PairStat> = pairs.iter().collect();
    hot.sort_by(|a, b| {
        b.within[short_idx]
            .cmp(&a.within[short_idx])
            .then((a.start, a.end).cmp(&(b.start, b.end)))
    });
    hot.truncate(HOT_PAIRS);

    let all_table = ctx.form_table(&ctx.per_insn(None));
    let all_adm = ctx.gap_admission_with(None, &[], 0);
    let hot_tables: Vec<(&PairStat, FormTable, GapAdmission)> = hot
        .iter()
        .map(|p| {
            let key = Some((p.start, p.end));
            (
                *p,
                ctx.form_table(&ctx.per_insn(key)),
                ctx.gap_admission_with(key, &[], 0),
            )
        })
        .collect();

    // Per-vCPU (thread) summary.
    #[derive(Default)]
    struct VcpuStat {
        closed: u64,
        closed_insns: u64,
        other_insns: u64,
        elided: u64,
    }
    let mut vcpus: BTreeMap<u32, VcpuStat> = BTreeMap::new();
    for g in &trace.gaps {
        let v = vcpus.entry(g.vcpu).or_default();
        v.elided += g.elided;
        if g.closed() {
            v.closed += 1;
            v.closed_insns += g.len;
        } else {
            v.other_insns += g.len;
        }
    }

    let mut ends: BTreeMap<i32, u64> = BTreeMap::new();
    for g in &closed {
        *ends.entry(g.end).or_default() += 1;
    }
    let mut syscalls: Vec<(u32, u64)> = trace.syscalls.iter().map(|(a, b)| (*a, *b)).collect();
    syscalls.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let syscall_total: u64 = syscalls.iter().map(|s| s.1).sum();
    let limits_label: Vec<String> = trace.limits.iter().map(|l| format!("≤{l}")).collect();
    let limit = trace.short_limit();
    let invalid_words = ctx
        .form_of
        .values()
        .filter(|f| f.form == kjit_harness::a64_forms::INVALID_FORM)
        .count();

    // ---- JSON ----
    let mut j = String::from("{\n");
    writeln!(
        j,
        "  \"trace\": {},",
        json_str(&trace_path.display().to_string())
    )
    .unwrap();
    writeln!(j, "  \"bucket_limits\": {:?},", trace.limits).unwrap();
    writeln!(
        j,
        "  \"elided_syscalls\": {:?},",
        trace.elided.iter().collect::<Vec<_>>()
    )
    .unwrap();
    let totals: Vec<String> = trace
        .totals
        .iter()
        .map(|(k, v)| format!("{}:{v}", json_str(k)))
        .collect();
    writeln!(j, "  \"tracer_totals\": {{{}}},", totals.join(",")).unwrap();
    writeln!(
        j,
        "  \"distinct\": {{\"insns\":{},\"words\":{},\"invalid_words\":{invalid_words},\"shapes\":{}}},",
        trace.insns.len(),
        words.len(),
        trace.shapes.len()
    )
    .unwrap();
    let admit_err_json: Vec<String> = admit_errors
        .iter()
        .map(|(k, v)| format!("{}:{v}", json_str(k)))
        .collect();
    writeln!(
        j,
        "  \"admit_errors_by_message\": {{{}}},",
        admit_err_json.join(",")
    )
    .unwrap();
    writeln!(
        j,
        "  \"gaps\": {{\"closed\":{},\"closed_insns\":{},\"thread_start\":{},\"thread_start_insns\":{},\"open\":{},\"open_insns\":{}}},",
        closed.len(),
        sum(&closed),
        thread_start.len(),
        sum(&thread_start),
        open.len(),
        sum(&open)
    )
    .unwrap();
    let sc: Vec<String> = syscalls
        .iter()
        .map(|(nr, n)| {
            format!(
                "{{\"nr\":{nr},\"name\":{},\"count\":{n},\"elided\":{},\"ends_closed_gaps\":{}}}",
                json_str(syscall_name(*nr as i32)),
                trace.elided.contains(nr),
                ends.get(&(*nr as i32)).copied().unwrap_or(0)
            )
        })
        .collect();
    writeln!(j, "  \"syscalls\": [\n    {}\n  ],", sc.join(",\n    ")).unwrap();
    writeln!(j, "  \"gap_dist_closed\": {},", json_pair(&trace, &overall)).unwrap();
    let pj: Vec<String> = pairs.iter().map(|p| json_pair(&trace, p)).collect();
    writeln!(j, "  \"pairs\": [\n    {}\n  ],", pj.join(",\n    ")).unwrap();
    let vj: Vec<String> = vcpus
        .iter()
        .map(|(c, v)| {
            format!(
                "{{\"vcpu\":{c},\"closed_gaps\":{},\"closed_insns\":{},\"other_insns\":{},\"elided_syscalls\":{}}}",
                v.closed, v.closed_insns, v.other_insns, v.elided
            )
        })
        .collect();
    writeln!(j, "  \"vcpus\": [{}],", vj.join(",")).unwrap();
    writeln!(
        j,
        "  \"short_gaps\": {{\"limit\":{limit},\"gaps\":{},\"insns\":{},\"fully_admitted_gaps\":{},\"fully_admitted_gap_insns\":{},\"forms\":{}}},",
        all_adm.gaps,
        all_adm.insns,
        all_adm.full_gaps,
        all_adm.full_insns,
        json_form_table(&ctx, &all_table, usize::MAX)
    )
    .unwrap();
    let hj: Vec<String> = hot_tables
        .iter()
        .map(|(p, t, a)| {
            format!(
                "{{\"pair\":{},\"gaps\":{},\"insns\":{},\"fully_admitted_gaps\":{},\"fully_admitted_gap_insns\":{},\"forms\":{}}}",
                json_pair(&trace, p),
                a.gaps,
                a.insns,
                a.full_gaps,
                a.full_insns,
                json_form_table(&ctx, t, usize::MAX)
            )
        })
        .collect();
    writeln!(j, "  \"hot_pairs\": [\n  {}\n  ]", hj.join(",\n  ")).unwrap();
    j.push_str("}\n");

    // ---- Markdown ----
    let mut m = String::new();
    m.push_str("# E1 dynamic trace: instructions between syscalls\n\n");
    writeln!(
        m,
        "Trace: `{}` (run parameters in `run-meta.txt` next to it). A *gap* is the \
instruction stream of one thread between two syscalls; its length counts every executed \
instruction including the terminating `svc`. Only closed gaps (syscall on both ends) are \
analysed below. Elided syscalls ({}) are vDSO calls on native arm64 but real SVCs under QEMU \
7.2 linux-user: they are counted in the histogram but do not end a gap. Length buckets: {}.\n",
        trace_path.display(),
        trace
            .elided
            .iter()
            .map(|nr| nr_label(*nr as i32))
            .collect::<Vec<_>>()
            .join(", "),
        limits_label.join(", ")
    )
    .unwrap();

    m.push_str("## Trace volume\n\n| metric | value |\n|---|---|\n");
    writeln!(m, "| syscalls (all, incl. elided) | {syscall_total} |").unwrap();
    writeln!(
        m,
        "| closed gaps / insns | {} / {} |",
        closed.len(),
        sum(&closed)
    )
    .unwrap();
    writeln!(
        m,
        "| thread-start gaps / insns (not analysed) | {} / {} |",
        thread_start.len(),
        sum(&thread_start)
    )
    .unwrap();
    writeln!(
        m,
        "| open gaps at exit / insns (not analysed) | {} / {} |",
        open.len(),
        sum(&open)
    )
    .unwrap();
    writeln!(
        m,
        "| distinct insns (pc) / words / invalid words | {} / {} / {invalid_words} |",
        trace.insns.len(),
        words.len()
    )
    .unwrap();
    writeln!(
        m,
        "| distinct closed-gap shapes (≤{limit}) | {} |",
        trace.shapes.len()
    )
    .unwrap();
    for (k, v) in &trace.totals {
        writeln!(m, "| tracer `{k}` | {v} |").unwrap();
    }
    writeln!(
        m,
        "| `admit_word` errors (distinct insns) | {} |",
        admit_errors.values().sum::<usize>()
    )
    .unwrap();
    m.push('\n');
    for (msg, n) in &admit_errors {
        writeln!(m, "- `admit_word` error on {n} insns: {msg}").unwrap();
    }

    m.push_str("### Threads (vCPU index)\n\n| vcpu | closed gaps | closed-gap insns | other insns | elided syscalls |\n|---|---|---|---|---|\n");
    for (c, v) in &vcpus {
        writeln!(
            m,
            "| {c} | {} | {} | {} | {} |",
            v.closed, v.closed_insns, v.other_insns, v.elided
        )
        .unwrap();
    }
    m.push('\n');

    m.push_str("## 1. Syscall histogram\n\n| nr | name | count | % | ends closed gaps | elided |\n|---|---|---|---|---|---|\n");
    for (nr, n) in &syscalls {
        writeln!(
            m,
            "| {nr} | {} | {n} | {:.1} | {} | {} |",
            syscall_name(*nr as i32),
            pct(*n, syscall_total),
            ends.get(&(*nr as i32)).copied().unwrap_or(0),
            if trace.elided.contains(nr) { "yes" } else { "" }
        )
        .unwrap();
    }
    m.push('\n');

    writeln!(
        m,
        "## 2. Gap length (dynamic instructions)\n\nLast column: % of the row's dynamic \
instructions that lie in gaps {}. Pairs: top {TOP_PAIRS_TABLE} of {} by gap count.\n",
        limits_label.join(" / "),
        pairs.len()
    )
    .unwrap();
    m.push_str("| gaps | n | min | median | p90 | p99 | max | dyn insns | % insns in gaps within limits |\n|---|---|---|---|---|---|---|---|---|\n");
    md_pair_row(&mut m, "**all closed**", &overall);
    for p in pairs.iter().take(TOP_PAIRS_TABLE) {
        md_pair_row(&mut m, &pair_label(p.start, p.end), p);
    }
    m.push('\n');

    writeln!(
        m,
        "## 3. Instruction forms in closed gaps ≤{limit} (all pairs)\n\n\
`admitted` is `admit_word(word, pc)` (current decoder + reg-virt): `yes` = `Ok(Ok(_))`, \
`no` = `Ok(Err(_))` (Unsupported runtime exit). `cum %` = share of dynamic instructions \
covered by forms 1..k. Branch, call and return words (`b`, `bl`, `blr`, `br`, `ret`, \
`svc`) count as admitted: the translator lowers them to runtime exits, so a *fully admitted* \
gap is one with no Unsupported exit, not one that runs as a single fragment.\n"
    )
    .unwrap();
    writeln!(
        m,
        "Gaps ≤{limit} whose every executed instruction is admitted: {} of {} ({:.1}%), \
covering {:.1}% of their dynamic instructions.\n",
        all_adm.full_gaps,
        all_adm.gaps,
        pct(all_adm.full_gaps, all_adm.gaps),
        pct(all_adm.full_insns, all_adm.insns)
    )
    .unwrap();
    md_images(&mut m, &all_table);
    writeln!(m, "### Top {TOP_FORMS} forms by dynamic count\n").unwrap();
    md_form_table(&mut m, &ctx, &all_table, TOP_FORMS);
    writeln!(
        m,
        "### Next forms to add (top {TOP_NEXT_FORMS} non-admitted by dynamic count)\n"
    )
    .unwrap();
    md_next_forms(&mut m, &ctx, &all_table, TOP_NEXT_FORMS);
    md_add_curve(&mut m, &ctx, None, &all_table);

    writeln!(
        m,
        "## 4. Hottest gap pairs (by dynamic instructions in gaps ≤{limit})\n"
    )
    .unwrap();
    for (p, t, a) in &hot_tables {
        writeln!(m, "### {}\n", pair_label(p.start, p.end)).unwrap();
        m.push_str("| gaps | n | min | median | p90 | p99 | max | dyn insns | % insns in gaps within limits |\n|---|---|---|---|---|---|---|---|---|\n");
        md_pair_row(&mut m, "this pair", p);
        m.push('\n');
        writeln!(
            m,
            "Fully admitted gaps ≤{limit}: {} of {} ({:.1}%).\n",
            a.full_gaps,
            a.gaps,
            pct(a.full_gaps, a.gaps)
        )
        .unwrap();
        md_images(&mut m, t);
        md_form_table(&mut m, &ctx, t, TOP_PAIR_FORMS);
        md_next_forms(&mut m, &ctx, t, 10);
        md_add_curve(&mut m, &ctx, Some((p.start, p.end)), t);
    }

    std::fs::create_dir_all(out_dir)
        .map_err(|err| format!("failed to create {}: {err}", out_dir.display()))?;
    let json_path = out_dir.join("report.json");
    let md_path = out_dir.join("report.md");
    std::fs::write(&json_path, j)
        .map_err(|err| format!("failed to write {}: {err}", json_path.display()))?;
    std::fs::write(&md_path, &m)
        .map_err(|err| format!("failed to write {}: {err}", md_path.display()))?;
    eprintln!("wrote {} and {}", md_path.display(), json_path.display());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [trace, out] = args.as_slice() else {
        eprintln!("usage: e1-report <trace.txt> <out-dir>");
        std::process::exit(2);
    };
    if let Err(err) = run(&PathBuf::from(trace), &PathBuf::from(out)) {
        eprintln!("e1-report: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_trace;

    const TRACE: &str = "V 1\nB 256 1000 10000\nX 113\nM 0 /bin/x\n\
I 0 1000 d503201f 0 0\nI 1 1004 d4000001 0 4\nS 63 2\nS 113 1\n\
G 0 -1 63 5 0 -1\nG 0 63 63 3 1 0\nG 0 63 -1 1 0 -1\nH 0 2 0 1\n\
C 63 63 0 0 2\nC 63 63 0 1 1\nT forks_not_traced 0\nE\n";

    #[test]
    fn parses_and_cross_checks_trace() {
        let t = parse_trace(TRACE).unwrap();
        assert_eq!(t.insns.len(), 2);
        assert_eq!(t.gaps.iter().filter(|g| g.closed()).count(), 1);
        assert_eq!(t.bucket_of(256), 0);
        assert_eq!(t.bucket_of(257), 1);
        assert_eq!(t.bucket_of(10001), 3);
    }

    #[test]
    fn rejects_counts_that_disagree_with_gap_lengths() {
        let bad = TRACE.replace("C 63 63 0 1 1", "C 63 63 0 1 2");
        assert!(parse_trace(&bad)
            .err()
            .expect("trace must be rejected")
            .contains("disagree"));
    }

    #[test]
    fn rejects_truncated_trace() {
        let bad = TRACE.replace("E\n", "");
        assert!(parse_trace(&bad)
            .err()
            .expect("trace must be rejected")
            .contains("end marker"));
    }
}
