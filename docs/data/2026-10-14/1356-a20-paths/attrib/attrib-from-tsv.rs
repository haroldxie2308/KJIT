//! EXPERIMENT (exp/redis-attrib), not for main.
//!
//! Per-instruction lowering classes for the instructions an E1 trace executed.
//!
//!   attrib --trace trace.txt --map CONTAINER_PATH=HOST_ELF ... --out FILE.tsv
//!
//! Reads the aggregate trace of `tools/e1-trace/kjit_trace.c` (records V B X M I S G H C J K
//! T E). For every distinct executed instruction it prints one TSV row: the number of
//! dynamic executions in "request gaps" and the words the shared translator emits for it
//! (rephrase -> reg-virt, hot path: the cold region and the exit groups are not counted,
//! the dispatch template counts its nine main-probe-hit words). Lowering is read from the
//! translator: fragments are compiled from entries picked so every executed word is
//! covered, over the real ELF text (not only the executed words), so the CFG is the one
//! the kernel's translation of the same entry would build.
//!
//! "Request gaps": closed gaps whose start and end syscalls are both in {read 63,
//! write 64, epoll_pwait 22} and whose length is within the largest bucket (10000).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;

use kjit_harness::a64_forms::disassemble;
use kjit_harness::shared::trans::cfg::{admit_word, build_cfg};
use kjit_harness::shared::trans::input::{
    CodeProvider, CodeReadError, TranslationRequest, TranslationTrigger,
};
use kjit_harness::shared::trans::reg_virt::virtualize_registers;
use kjit_harness::shared::trans::rephrase::{rephrase, RephrasedInsnKind};

const REQUEST_SYSCALLS: [i32; 3] = [22, 63, 64];

struct Insn {
    pc: u64,
    word: u32,
    image: usize,
    file_off: u64,
}

struct Region {
    pc: u64,
    bytes: Vec<u8>,
}

struct Regions(Vec<Region>);

impl CodeProvider for Regions {
    fn entry_addr(&self) -> u64 {
        0
    }
    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        for r in &self.0 {
            if pc >= r.pc && pc - r.pc + dst.len() as u64 <= r.bytes.len() as u64 {
                let o = (pc - r.pc) as usize;
                dst.copy_from_slice(&r.bytes[o..o + dst.len()]);
                return Ok(());
            }
        }
        Err(CodeReadError::Unmapped { pc, len: dst.len() })
    }
}

fn die(msg: String) -> ! {
    eprintln!("attrib: {msg}");
    std::process::exit(1);
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

/// Executable PT_LOAD segments: (file offset, vaddr, filesz).
fn exec_segments(elf: &[u8]) -> Vec<(u64, u64, u64)> {
    if &elf[0..4] != b"\x7fELF" || elf[4] != 2 {
        die("not an ELF64 file".into());
    }
    let phoff = u64_at(elf, 0x20) as usize;
    let phentsize = u16_at(elf, 0x36) as usize;
    let phnum = u16_at(elf, 0x38) as usize;
    let mut v = Vec::new();
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let (ty, flags) = (u32_at(elf, p), u32_at(elf, p + 4));
        if ty == 1 && flags & 1 != 0 {
            v.push((u64_at(elf, p + 8), u64_at(elf, p + 0x10), u64_at(elf, p + 0x20)));
        }
    }
    v
}

#[derive(Default, Clone)]
struct Lowering {
    /// Emitted body words per class on the hot path.
    c: BTreeMap<&'static str, u32>,
}

fn class_of(kind: RephrasedInsnKind, text: &str, dispatch_seen: &mut u32) -> Option<&'static str> {
    use RephrasedInsnKind as K;
    Some(match kind {
        K::Original => "user_op",
        K::UserSynthetic => "user_synth",
        K::UserAccess => "user_access",
        K::BudgetCheck => "budget",
        K::AlignCheck => "align",
        K::RangeCheck => "range",
        K::WindowAccess => "window_access",
        K::LinkSlot { .. } => "link_slot",
        K::DispatchTarget => "dispatch_target",
        K::DispatchLookup => {
            *dispatch_seen += 1;
            if *dispatch_seen <= 9 {
                "dispatch_lookup"
            } else {
                return None;
            }
        }
        K::RuntimeExitPayload | K::RuntimeExitBranch => return None,
        K::RegVirtHelper => {
            if text.starts_with("ldr") && text.contains("[sp") {
                "fill"
            } else if text.starts_with("str") && text.contains("[sp") {
                "spill"
            } else {
                "helper_other"
            }
        }
    })
}

fn main() {
    let mut trace_path = String::new();
    let mut out_path = String::new();
    let mut maps: HashMap<String, String> = HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--trace" => trace_path = args.next().unwrap(),
            "--out" => out_path = args.next().unwrap(),
            "--map" => {
                let m = args.next().unwrap();
                let (k, v) = m.split_once('=').unwrap_or_else(|| die(format!("bad --map {m}")));
                maps.insert(k.to_string(), v.to_string());
            }
            other => die(format!("unknown argument {other}")),
        }
    }
    if trace_path.is_empty() || out_path.is_empty() {
        die("usage: attrib --trace T --map CPATH=HOSTELF ... --out OUT.tsv".into());
    }

    // ---- parse the lowering TSV of the 2026-10-13 15:25 entry (one row per executed instruction) ----
    let text = fs::read_to_string(&trace_path).unwrap_or_else(|e| die(format!("{trace_path}: {e}")));
    let mut images: Vec<String> = Vec::new();
    let mut insns: Vec<Insn> = Vec::new();
    let mut count: Vec<u64> = Vec::new();
    let mut tsv_vaddr: Vec<u64> = Vec::new();
    let ind_pairs: Vec<(usize, usize, u64)> = Vec::new();
    let ind_changes: HashMap<usize, u64> = HashMap::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let image = match images.iter().position(|p| p == f[0]) {
            Some(i) => i,
            None => {
                images.push(f[0].to_string());
                images.len() - 1
            }
        };
        insns.push(Insn {
            pc: u64::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap(),
            word: u32::from_str_radix(f[4], 16).unwrap(),
            image,
            file_off: 0,
        });
        tsv_vaddr.push(u64::from_str_radix(f[1].trim_start_matches("0x"), 16).unwrap());
        count.push(f[3].parse().unwrap());
    }

    // ---- code regions per image ----
    let mut elf_cache: HashMap<usize, (Vec<u8>, Vec<(u64, u64, u64)>)> = HashMap::new();
    let mut regions: Vec<Region> = Vec::new();
    let mut elf_vaddr: HashMap<usize, u64> = HashMap::new(); // insn id -> ELF vaddr
    let mut bias_seen: BTreeSet<(usize, u64)> = BTreeSet::new();
    let executed: Vec<usize> = (0..insns.len()).filter(|&i| count[i] > 0).collect();
    for &i in &executed {
        let ins = &insns[i];
        let path = &images[ins.image];
        let host = maps
            .get(path)
            .unwrap_or_else(|| die(format!("no --map for image `{path}` (insn pc {:#x})", ins.pc)));
        let entry = elf_cache.entry(ins.image).or_insert_with(|| {
            let b = fs::read(host).unwrap_or_else(|e| die(format!("{host}: {e}")));
            let segs = exec_segments(&b);
            (b, segs)
        });
        let vaddr = tsv_vaddr[i];
        let seg = entry
            .1
            .iter()
            .find(|s| vaddr >= s.1 && vaddr < s.1 + s.2)
            .unwrap_or_else(|| die(format!("insn {:#x} vaddr {:#x} in no exec segment of {path}", ins.pc, vaddr)));
        let file_off = seg.0 + (vaddr - seg.1);
        elf_vaddr.insert(i, vaddr);
        let bias = ins.pc - vaddr;
        if bias_seen.insert((ins.image, bias)) {
            let bytes = entry.0[seg.0 as usize..(seg.0 + seg.2) as usize].to_vec();
            regions.push(Region { pc: bias + seg.1, bytes });
        }
        // The word in the trace must be the word in the file.
        let o = file_off as usize;
        let fw = u32::from_le_bytes(entry.0[o..o + 4].try_into().unwrap());
        if fw != ins.word {
            die(format!("word mismatch at {:#x}: trace {:08x} file {:08x}", ins.pc, ins.word, fw));
        }
    }
    let code = Regions(regions);

    // ---- cover every executed, admitted word with compiled fragments ----
    let mut exec_pcs: Vec<(u64, usize)> = executed.iter().map(|&i| (insns[i].pc, i)).collect();
    exec_pcs.sort();
    let mut lowering: HashMap<u64, Lowering> = HashMap::new(); // by pc
    let mut unsupported: HashSet<u64> = HashSet::new();
    let mut failed_entries = 0u32;
    let mut fragments = 0u32;
    let mut pending_words: Vec<u32> = Vec::new();
    // First pass: compile; keep (kind, ori_pc, word) lists; disassemble later in one go.
    struct Emitted {
        kind: RephrasedInsnKind,
        ori_pc: u64,
        word: u32,
    }
    let mut per_pc: HashMap<u64, Vec<Emitted>> = HashMap::new();
    for &(pc, _) in &exec_pcs {
        let w = {
            let mut b = [0u8; 4];
            code.read_exact(pc, &mut b).unwrap();
            u32::from_le_bytes(b)
        };
        match admit_word(w, pc) {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                unsupported.insert(pc);
                continue;
            }
            Err(e) => die(format!("admit_word {pc:#x}: {e}")),
        }
        if per_pc.contains_key(&pc) {
            continue;
        }
        let request = TranslationRequest {
            entry_pc: pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let cfg = match build_cfg(&request, &code) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("attrib: cfg {pc:#x}: {e}");
                failed_entries += 1;
                continue;
            }
        };
        let rephrased = match rephrase(cfg) {
            Ok(r) => r,
            Err(e) => die(format!("rephrase {pc:#x}: {e:?}")),
        };
        let virt = match virtualize_registers(rephrased) {
            Ok(v) => v,
            Err(e) => die(format!("reg-virt {pc:#x}: {e:?}")),
        };
        fragments += 1;
        let mut local: HashMap<u64, Vec<Emitted>> = HashMap::new();
        for block in virt.iter() {
            for r in block.insns.iter() {
                let word = r.insn.encode().unwrap_or_else(|e| die(format!("encode: {e:?}")));
                local.entry(r.ori_pc).or_default().push(Emitted {
                    kind: r.kind,
                    ori_pc: r.ori_pc,
                    word,
                });
            }
        }
        // Lowering is context-free: keep the first fragment's sequence for a pc.
        for (opc, v) in local {
            if !per_pc.contains_key(&opc) {
                for e in &v {
                    pending_words.push(e.word);
                }
                per_pc.insert(opc, v);
            }
        }
    }

    // ---- disassemble the distinct emitted words once ----
    let mut distinct: Vec<u32> = pending_words.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let dis = disassemble(&distinct).unwrap_or_else(|e| die(e));
    let text_of: HashMap<u32, String> = distinct
        .iter()
        .zip(dis)
        .map(|(&w, t)| (w, t.unwrap_or_default()))
        .collect();
    // And the original words.
    let mut owords: Vec<u32> = executed.iter().map(|&i| insns[i].word).collect();
    owords.sort_unstable();
    owords.dedup();
    let odis = disassemble(&owords).unwrap_or_else(|e| die(e));
    let otext: HashMap<u32, String> = owords
        .iter()
        .zip(odis)
        .map(|(&w, t)| (w, t.unwrap_or_default()))
        .collect();

    for (&pc, v) in per_pc.iter() {
        let mut low = Lowering::default();
        let mut dispatch_seen = 0u32;
        for e in v {
            let t = text_of.get(&e.word).map(String::as_str).unwrap_or("");
            if let Some(cls) = class_of(e.kind, t, &mut dispatch_seen) {
                *low.c.entry(cls).or_default() += 1;
            }
            let _ = e.ori_pc;
        }
        lowering.insert(pc, low);
    }

    // ---- output ----
    let classes = [
        "user_op", "user_synth", "user_access", "fill", "spill", "helper_other", "budget",
        "align", "range", "pan_toggle", "window_access", "link_slot", "dispatch_target", "dispatch_lookup",
    ];
    let mut out = String::new();
    write!(out, "image\tvaddr\tpc\tcount\tword\tsupported\ttext").unwrap();
    for c in classes {
        write!(out, "\t{c}").unwrap();
    }
    out.push('\n');
    let mut missing = 0u32;
    for &i in &executed {
        let ins = &insns[i];
        let sup = !unsupported.contains(&ins.pc);
        let low = lowering.get(&ins.pc);
        if sup && low.is_none() {
            missing += 1;
        }
        write!(
            out,
            "{}\t{:#x}\t{:#x}\t{}\t{:08x}\t{}\t{}",
            images[ins.image],
            elf_vaddr[&i],
            ins.pc,
            count[i],
            ins.word,
            if sup { 1 } else { 0 },
            otext.get(&ins.word).map(String::as_str).unwrap_or("?")
        )
        .unwrap();
        for c in classes {
            write!(out, "\t{}", low.and_then(|l| l.c.get(c)).copied().unwrap_or(0)).unwrap();
        }
        out.push('\n');
    }
    fs::write(&out_path, out).unwrap_or_else(|e| die(format!("{out_path}: {e}")));

    // Indirect-branch sites: id, pc, executions, distinct targets, last-target changes.
    let mut sites: BTreeMap<usize, (u64, usize)> = BTreeMap::new();
    for &(site, _tgt, n) in &ind_pairs {
        let e = sites.entry(site).or_default();
        e.0 += n;
        e.1 += 1;
    }
    let mut s = String::from("image\tvaddr\tpc\tword\ttext\texecs\ttargets\tchanges\n");
    for (&site, &(execs, targets)) in &sites {
        let ins = &insns[site];
        let v = elf_vaddr.get(&site).copied().unwrap_or(0);
        writeln!(
            s,
            "{}\t{:#x}\t{:#x}\t{:08x}\t{}\t{}\t{}\t{}",
            images[ins.image],
            v,
            ins.pc,
            ins.word,
            otext.get(&ins.word).map(String::as_str).unwrap_or("?"),
            execs,
            targets,
            ind_changes.get(&site).copied().unwrap_or(0)
        )
        .unwrap();
    }
    fs::write(format!("{out_path}.indirect"), s).unwrap();
    eprintln!(
        "attrib: {} executed insns, {} fragments compiled, {} entries failed, {} unsupported pcs, {} supported pcs without lowering",
        executed.len(),
        fragments,
        failed_entries,
        unsupported.len(),
        missing
    );
}
