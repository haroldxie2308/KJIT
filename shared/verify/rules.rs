//! Per-instruction facts of the verifier, derived from the generated A64 forms and
//! the ABI constants only. Nothing here knows how the translator produced a word.

use crate::shared::abi::{
    pt_regs_x_slot_offset, reg_virt_stack_backed_slot_offset, PAN_WINDOW_RANGE_TOP_BIT,
    REG_VIRT_SCRATCH_GPR_END, REG_VIRT_SCRATCH_GPR_START, REG_VIRT_STACK_BACKED_REG_END,
    REG_VIRT_STACK_BACKED_REG_START, RUNTIME_FRAME_BUDGET_OFFSET, RUNTIME_FRAME_ENTRY_ADDR_OFFSET,
    RUNTIME_FRAME_PT_REGS_PTR_OFFSET, USER_VA_BITS,
};
use crate::shared::arm64::{A64Insn, A64Mem, A64OperandRole, A64Reg, A64Reg31Mode};

/// What one decoded word is, as far as the safety rules care. Built by an exhaustive
/// match over the generated forms, so a new form fails to compile until it is
/// classified here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Form {
    /// Pure register data processing: reads/writes general registers and NZCV only.
    Alu,
    Nop,
    /// `DMB`/`DSB`/`ISB` (every generated CRm value; DSB without nXS): the one
    /// system-instruction group besides NOP and MRS TPIDR_EL0. Same effect at EL1
    /// as at EL0 for every observer of user memory; no register, memory or PSTATE
    /// effect. Every other barrier-like or system instruction is undecodable.
    Barrier,
    /// `MRS Xt, TPIDR_EL0`: the generated form is constrained to that one register.
    MrsTpidrEl0,
    /// `ADR`/`ADRP`: would put a kernel (fragment) address in a user register.
    PcRelative,
    /// PC-relative direct branch; `delta` is the byte offset from the branch.
    Branch {
        delta: i64,
        conditional: bool,
    },
    /// Unprivileged `LDTR*`/`STTR*`: the only forms allowed to touch user memory.
    UserAccess {
        mem: A64Mem,
    },
    /// A user-code form the translator only ever lowers (loads/stores to
    /// `LDTR*`/`STTR*`, PRFM and BTI to a `NOP`): never valid in a fragment, not
    /// even on runtime memory, because it has no role there. Includes the
    /// acquire/release forms (LDAR*, STLR*, LDAPR*): a privileged ordered access at
    /// EL1 would bypass the EL0 permission check.
    UserOnly,
    /// Every other load/store: allowed only on the runtime frame or `pt_regs`.
    /// `bytes` is the whole contiguous footprint (16 for a 64-bit pair).
    RuntimeAccess {
        mem: A64Mem,
        bytes: u32,
        store: bool,
    },
    Call,
    IndirectBranch,
    Exception,
    /// An LSE single-register atomic (LD<op>, SWP, CAS; A8): a privileged access to
    /// user memory. Allowed only as the atomic of an exact PAN window, based on the
    /// window's range-checked register `rn`.
    WindowAtomic {
        rn: A64Reg,
    },
    /// `msr pan, #0`: allowed only as the start of an exact PAN window.
    PanClear,
    /// `msr pan, #1`: allowed only as a window's end or a PAN stub's first word.
    PanSet,
    /// Any other `MSR (immediate)` encoding the generated form decodes (PSTATE.PAN
    /// with CRm other than 0/1): never allowed.
    MsrOther,
}

pub(super) fn classify(insn: A64Insn) -> Form {
    match insn {
        // The one list of user-access forms (tmp/pipeline.md, "Privilege model").
        A64Insn::LdtrLdtr32LdstUnpriv { mem, .. }
        | A64Insn::LdtrLdtr64LdstUnpriv { mem, .. }
        | A64Insn::LdtrbLdtrb32LdstUnpriv { mem, .. }
        | A64Insn::LdtrhLdtrh32LdstUnpriv { mem, .. }
        | A64Insn::LdtrsbLdtrsb32LdstUnpriv { mem, .. }
        | A64Insn::LdtrsbLdtrsb64LdstUnpriv { mem, .. }
        | A64Insn::LdtrshLdtrsh32LdstUnpriv { mem, .. }
        | A64Insn::LdtrshLdtrsh64LdstUnpriv { mem, .. }
        | A64Insn::LdtrswLdtrsw64LdstUnpriv { mem, .. }
        | A64Insn::SttrSttr32LdstUnpriv { mem, .. }
        | A64Insn::SttrSttr64LdstUnpriv { mem, .. }
        | A64Insn::SttrbSttrb32LdstUnpriv { mem, .. }
        | A64Insn::SttrhSttrh32LdstUnpriv { mem, .. } => Form::UserAccess { mem },

        // User-code memory forms (A7b). The runtime never needs them and a user
        // access must be `LDTR*`/`STTR*`, so they are rejected wherever they appear.
        A64Insn::LdpGenLdp32LdstpairPost { .. }
        | A64Insn::LdpGenLdp32LdstpairPre { .. }
        | A64Insn::LdpGenLdp32LdstpairOff { .. }
        | A64Insn::StpGenStp32LdstpairPost { .. }
        | A64Insn::StpGenStp32LdstpairPre { .. }
        | A64Insn::StpGenStp32LdstpairOff { .. }
        | A64Insn::LdpswLdpsw64LdstpairPost { .. }
        | A64Insn::LdpswLdpsw64LdstpairPre { .. }
        | A64Insn::LdpswLdpsw64LdstpairOff { .. }
        | A64Insn::LdrbImmLdrb32LdstImmpost { .. }
        | A64Insn::LdrbImmLdrb32LdstImmpre { .. }
        | A64Insn::LdrbImmLdrb32LdstPos { .. }
        | A64Insn::StrbImmStrb32LdstImmpost { .. }
        | A64Insn::StrbImmStrb32LdstImmpre { .. }
        | A64Insn::StrbImmStrb32LdstPos { .. }
        | A64Insn::LdrhImmLdrh32LdstImmpost { .. }
        | A64Insn::LdrhImmLdrh32LdstImmpre { .. }
        | A64Insn::LdrhImmLdrh32LdstPos { .. }
        | A64Insn::StrhImmStrh32LdstImmpost { .. }
        | A64Insn::StrhImmStrh32LdstImmpre { .. }
        | A64Insn::StrhImmStrh32LdstPos { .. }
        | A64Insn::LdrsbImmLdrsb32LdstImmpost { .. }
        | A64Insn::LdrsbImmLdrsb64LdstImmpost { .. }
        | A64Insn::LdrsbImmLdrsb32LdstImmpre { .. }
        | A64Insn::LdrsbImmLdrsb64LdstImmpre { .. }
        | A64Insn::LdrsbImmLdrsb32LdstPos { .. }
        | A64Insn::LdrsbImmLdrsb64LdstPos { .. }
        | A64Insn::LdrshImmLdrsh32LdstImmpost { .. }
        | A64Insn::LdrshImmLdrsh64LdstImmpost { .. }
        | A64Insn::LdrshImmLdrsh32LdstImmpre { .. }
        | A64Insn::LdrshImmLdrsh64LdstImmpre { .. }
        | A64Insn::LdrshImmLdrsh32LdstPos { .. }
        | A64Insn::LdrshImmLdrsh64LdstPos { .. }
        | A64Insn::LdrswImmLdrsw64LdstImmpost { .. }
        | A64Insn::LdrswImmLdrsw64LdstImmpre { .. }
        | A64Insn::LdrswImmLdrsw64LdstPos { .. }
        | A64Insn::LdurGenLdur32LdstUnscaled { .. }
        | A64Insn::LdurGenLdur64LdstUnscaled { .. }
        | A64Insn::SturGenStur32LdstUnscaled { .. }
        | A64Insn::SturGenStur64LdstUnscaled { .. }
        | A64Insn::LdurbLdurb32LdstUnscaled { .. }
        | A64Insn::SturbSturb32LdstUnscaled { .. }
        | A64Insn::LdurhLdurh32LdstUnscaled { .. }
        | A64Insn::SturhSturh32LdstUnscaled { .. }
        | A64Insn::LdursbLdursb32LdstUnscaled { .. }
        | A64Insn::LdursbLdursb64LdstUnscaled { .. }
        | A64Insn::LdurshLdursh32LdstUnscaled { .. }
        | A64Insn::LdurshLdursh64LdstUnscaled { .. }
        | A64Insn::LdurswLdursw64LdstUnscaled { .. }
        | A64Insn::LdrRegGenLdr32LdstRegoff { .. }
        | A64Insn::LdrRegGenLdr64LdstRegoff { .. }
        | A64Insn::StrRegGenStr32LdstRegoff { .. }
        | A64Insn::StrRegGenStr64LdstRegoff { .. }
        | A64Insn::LdrbRegLdrb32bLdstRegoff { .. }
        | A64Insn::LdrbRegLdrb32blLdstRegoff { .. }
        | A64Insn::StrbRegStrb32bLdstRegoff { .. }
        | A64Insn::StrbRegStrb32blLdstRegoff { .. }
        | A64Insn::LdrhRegLdrh32LdstRegoff { .. }
        | A64Insn::StrhRegStrh32LdstRegoff { .. }
        | A64Insn::LdrsbRegLdrsb32bLdstRegoff { .. }
        | A64Insn::LdrsbRegLdrsb32blLdstRegoff { .. }
        | A64Insn::LdrsbRegLdrsb64bLdstRegoff { .. }
        | A64Insn::LdrsbRegLdrsb64blLdstRegoff { .. }
        | A64Insn::LdrshRegLdrsh32LdstRegoff { .. }
        | A64Insn::LdrshRegLdrsh64LdstRegoff { .. }
        | A64Insn::LdrswRegLdrsw64LdstRegoff { .. }
        | A64Insn::LdrLitGenLdr32Loadlit { .. }
        | A64Insn::LdrLitGenLdr64Loadlit { .. }
        | A64Insn::LdrswLitLdrsw64Loadlit { .. }
        | A64Insn::PrfmImmPrfmPLdstPos { .. }
        | A64Insn::PrfmLitPrfmPLoadlit { .. }
        | A64Insn::PrfmRegPrfmPLdstRegoff { .. }
        // Acquire/release (A7c): lowered to `dmb ish; LDTR*/STTR*; dmb ish`.
        | A64Insn::LdarLdarLr32Ldstord { .. }
        | A64Insn::LdarLdarLr64Ldstord { .. }
        | A64Insn::LdarbLdarbLr32Ldstord { .. }
        | A64Insn::LdarhLdarhLr32Ldstord { .. }
        | A64Insn::StlrStlrSl32Ldstord { .. }
        | A64Insn::StlrStlrSl64Ldstord { .. }
        | A64Insn::StlrbStlrbSl32Ldstord { .. }
        | A64Insn::StlrhStlrhSl32Ldstord { .. }
        | A64Insn::LdaprLdapr32lMemop { .. }
        | A64Insn::LdaprLdapr64lMemop { .. }
        | A64Insn::LdaprbLdaprb32lMemop { .. }
        | A64Insn::LdaprhLdaprh32lMemop { .. }
        // BTI (A7d): rephrased to `NOP`, so the allowlisted hint space stays NOP.
        | A64Insn::BtiBtiHbHints { .. } => Form::UserOnly,

        // LSE single-register atomics (A8): LD<op>/SWP/CAS, every size and A/L/AL
        // variant (ST<op> is LD<op> with Rt = XZR). The one list of window atomics.
        A64Insn::LdaddLdadd32Memop { rn, .. }
        | A64Insn::LdaddLdadda32Memop { rn, .. }
        | A64Insn::LdaddLdaddal32Memop { rn, .. }
        | A64Insn::LdaddLdaddl32Memop { rn, .. }
        | A64Insn::LdaddLdadd64Memop { rn, .. }
        | A64Insn::LdaddLdadda64Memop { rn, .. }
        | A64Insn::LdaddLdaddal64Memop { rn, .. }
        | A64Insn::LdaddLdaddl64Memop { rn, .. }
        | A64Insn::LdaddbLdaddb32Memop { rn, .. }
        | A64Insn::LdaddbLdaddab32Memop { rn, .. }
        | A64Insn::LdaddbLdaddalb32Memop { rn, .. }
        | A64Insn::LdaddbLdaddlb32Memop { rn, .. }
        | A64Insn::LdaddhLdaddh32Memop { rn, .. }
        | A64Insn::LdaddhLdaddah32Memop { rn, .. }
        | A64Insn::LdaddhLdaddalh32Memop { rn, .. }
        | A64Insn::LdaddhLdaddlh32Memop { rn, .. }
        | A64Insn::LdclrLdclr32Memop { rn, .. }
        | A64Insn::LdclrLdclra32Memop { rn, .. }
        | A64Insn::LdclrLdclral32Memop { rn, .. }
        | A64Insn::LdclrLdclrl32Memop { rn, .. }
        | A64Insn::LdclrLdclr64Memop { rn, .. }
        | A64Insn::LdclrLdclra64Memop { rn, .. }
        | A64Insn::LdclrLdclral64Memop { rn, .. }
        | A64Insn::LdclrLdclrl64Memop { rn, .. }
        | A64Insn::LdclrbLdclrb32Memop { rn, .. }
        | A64Insn::LdclrbLdclrab32Memop { rn, .. }
        | A64Insn::LdclrbLdclralb32Memop { rn, .. }
        | A64Insn::LdclrbLdclrlb32Memop { rn, .. }
        | A64Insn::LdclrhLdclrh32Memop { rn, .. }
        | A64Insn::LdclrhLdclrah32Memop { rn, .. }
        | A64Insn::LdclrhLdclralh32Memop { rn, .. }
        | A64Insn::LdclrhLdclrlh32Memop { rn, .. }
        | A64Insn::LdeorLdeor32Memop { rn, .. }
        | A64Insn::LdeorLdeora32Memop { rn, .. }
        | A64Insn::LdeorLdeoral32Memop { rn, .. }
        | A64Insn::LdeorLdeorl32Memop { rn, .. }
        | A64Insn::LdeorLdeor64Memop { rn, .. }
        | A64Insn::LdeorLdeora64Memop { rn, .. }
        | A64Insn::LdeorLdeoral64Memop { rn, .. }
        | A64Insn::LdeorLdeorl64Memop { rn, .. }
        | A64Insn::LdeorbLdeorb32Memop { rn, .. }
        | A64Insn::LdeorbLdeorab32Memop { rn, .. }
        | A64Insn::LdeorbLdeoralb32Memop { rn, .. }
        | A64Insn::LdeorbLdeorlb32Memop { rn, .. }
        | A64Insn::LdeorhLdeorh32Memop { rn, .. }
        | A64Insn::LdeorhLdeorah32Memop { rn, .. }
        | A64Insn::LdeorhLdeoralh32Memop { rn, .. }
        | A64Insn::LdeorhLdeorlh32Memop { rn, .. }
        | A64Insn::LdsetLdset32Memop { rn, .. }
        | A64Insn::LdsetLdseta32Memop { rn, .. }
        | A64Insn::LdsetLdsetal32Memop { rn, .. }
        | A64Insn::LdsetLdsetl32Memop { rn, .. }
        | A64Insn::LdsetLdset64Memop { rn, .. }
        | A64Insn::LdsetLdseta64Memop { rn, .. }
        | A64Insn::LdsetLdsetal64Memop { rn, .. }
        | A64Insn::LdsetLdsetl64Memop { rn, .. }
        | A64Insn::LdsetbLdsetb32Memop { rn, .. }
        | A64Insn::LdsetbLdsetab32Memop { rn, .. }
        | A64Insn::LdsetbLdsetalb32Memop { rn, .. }
        | A64Insn::LdsetbLdsetlb32Memop { rn, .. }
        | A64Insn::LdsethLdseth32Memop { rn, .. }
        | A64Insn::LdsethLdsetah32Memop { rn, .. }
        | A64Insn::LdsethLdsetalh32Memop { rn, .. }
        | A64Insn::LdsethLdsetlh32Memop { rn, .. }
        | A64Insn::LdsmaxLdsmax32Memop { rn, .. }
        | A64Insn::LdsmaxLdsmaxa32Memop { rn, .. }
        | A64Insn::LdsmaxLdsmaxal32Memop { rn, .. }
        | A64Insn::LdsmaxLdsmaxl32Memop { rn, .. }
        | A64Insn::LdsmaxLdsmax64Memop { rn, .. }
        | A64Insn::LdsmaxLdsmaxa64Memop { rn, .. }
        | A64Insn::LdsmaxLdsmaxal64Memop { rn, .. }
        | A64Insn::LdsmaxLdsmaxl64Memop { rn, .. }
        | A64Insn::LdsmaxbLdsmaxb32Memop { rn, .. }
        | A64Insn::LdsmaxbLdsmaxab32Memop { rn, .. }
        | A64Insn::LdsmaxbLdsmaxalb32Memop { rn, .. }
        | A64Insn::LdsmaxbLdsmaxlb32Memop { rn, .. }
        | A64Insn::LdsmaxhLdsmaxh32Memop { rn, .. }
        | A64Insn::LdsmaxhLdsmaxah32Memop { rn, .. }
        | A64Insn::LdsmaxhLdsmaxalh32Memop { rn, .. }
        | A64Insn::LdsmaxhLdsmaxlh32Memop { rn, .. }
        | A64Insn::LdsminLdsmin32Memop { rn, .. }
        | A64Insn::LdsminLdsmina32Memop { rn, .. }
        | A64Insn::LdsminLdsminal32Memop { rn, .. }
        | A64Insn::LdsminLdsminl32Memop { rn, .. }
        | A64Insn::LdsminLdsmin64Memop { rn, .. }
        | A64Insn::LdsminLdsmina64Memop { rn, .. }
        | A64Insn::LdsminLdsminal64Memop { rn, .. }
        | A64Insn::LdsminLdsminl64Memop { rn, .. }
        | A64Insn::LdsminbLdsminb32Memop { rn, .. }
        | A64Insn::LdsminbLdsminab32Memop { rn, .. }
        | A64Insn::LdsminbLdsminalb32Memop { rn, .. }
        | A64Insn::LdsminbLdsminlb32Memop { rn, .. }
        | A64Insn::LdsminhLdsminh32Memop { rn, .. }
        | A64Insn::LdsminhLdsminah32Memop { rn, .. }
        | A64Insn::LdsminhLdsminalh32Memop { rn, .. }
        | A64Insn::LdsminhLdsminlh32Memop { rn, .. }
        | A64Insn::LdumaxLdumax32Memop { rn, .. }
        | A64Insn::LdumaxLdumaxa32Memop { rn, .. }
        | A64Insn::LdumaxLdumaxal32Memop { rn, .. }
        | A64Insn::LdumaxLdumaxl32Memop { rn, .. }
        | A64Insn::LdumaxLdumax64Memop { rn, .. }
        | A64Insn::LdumaxLdumaxa64Memop { rn, .. }
        | A64Insn::LdumaxLdumaxal64Memop { rn, .. }
        | A64Insn::LdumaxLdumaxl64Memop { rn, .. }
        | A64Insn::LdumaxbLdumaxb32Memop { rn, .. }
        | A64Insn::LdumaxbLdumaxab32Memop { rn, .. }
        | A64Insn::LdumaxbLdumaxalb32Memop { rn, .. }
        | A64Insn::LdumaxbLdumaxlb32Memop { rn, .. }
        | A64Insn::LdumaxhLdumaxh32Memop { rn, .. }
        | A64Insn::LdumaxhLdumaxah32Memop { rn, .. }
        | A64Insn::LdumaxhLdumaxalh32Memop { rn, .. }
        | A64Insn::LdumaxhLdumaxlh32Memop { rn, .. }
        | A64Insn::LduminLdumin32Memop { rn, .. }
        | A64Insn::LduminLdumina32Memop { rn, .. }
        | A64Insn::LduminLduminal32Memop { rn, .. }
        | A64Insn::LduminLduminl32Memop { rn, .. }
        | A64Insn::LduminLdumin64Memop { rn, .. }
        | A64Insn::LduminLdumina64Memop { rn, .. }
        | A64Insn::LduminLduminal64Memop { rn, .. }
        | A64Insn::LduminLduminl64Memop { rn, .. }
        | A64Insn::LduminbLduminb32Memop { rn, .. }
        | A64Insn::LduminbLduminab32Memop { rn, .. }
        | A64Insn::LduminbLduminalb32Memop { rn, .. }
        | A64Insn::LduminbLduminlb32Memop { rn, .. }
        | A64Insn::LduminhLduminh32Memop { rn, .. }
        | A64Insn::LduminhLduminah32Memop { rn, .. }
        | A64Insn::LduminhLduminalh32Memop { rn, .. }
        | A64Insn::LduminhLduminlh32Memop { rn, .. }
        | A64Insn::SwpSwp32Memop { rn, .. }
        | A64Insn::SwpSwpa32Memop { rn, .. }
        | A64Insn::SwpSwpal32Memop { rn, .. }
        | A64Insn::SwpSwpl32Memop { rn, .. }
        | A64Insn::SwpSwp64Memop { rn, .. }
        | A64Insn::SwpSwpa64Memop { rn, .. }
        | A64Insn::SwpSwpal64Memop { rn, .. }
        | A64Insn::SwpSwpl64Memop { rn, .. }
        | A64Insn::SwpbSwpb32Memop { rn, .. }
        | A64Insn::SwpbSwpab32Memop { rn, .. }
        | A64Insn::SwpbSwpalb32Memop { rn, .. }
        | A64Insn::SwpbSwplb32Memop { rn, .. }
        | A64Insn::SwphSwph32Memop { rn, .. }
        | A64Insn::SwphSwpah32Memop { rn, .. }
        | A64Insn::SwphSwpalh32Memop { rn, .. }
        | A64Insn::SwphSwplh32Memop { rn, .. }
        | A64Insn::CasCasC32Comswap { rn, .. }
        | A64Insn::CasCasaC32Comswap { rn, .. }
        | A64Insn::CasCasalC32Comswap { rn, .. }
        | A64Insn::CasCaslC32Comswap { rn, .. }
        | A64Insn::CasCasC64Comswap { rn, .. }
        | A64Insn::CasCasaC64Comswap { rn, .. }
        | A64Insn::CasCasalC64Comswap { rn, .. }
        | A64Insn::CasCaslC64Comswap { rn, .. }
        | A64Insn::CasbCasbC32Comswap { rn, .. }
        | A64Insn::CasbCasabC32Comswap { rn, .. }
        | A64Insn::CasbCasalbC32Comswap { rn, .. }
        | A64Insn::CasbCaslbC32Comswap { rn, .. }
        | A64Insn::CashCashC32Comswap { rn, .. }
        | A64Insn::CashCasahC32Comswap { rn, .. }
        | A64Insn::CashCasalhC32Comswap { rn, .. }
        | A64Insn::CashCaslhC32Comswap { rn, .. } => Form::WindowAtomic { rn },
        A64Insn::MsrImmMsrSiPstate { crm: 0 } => Form::PanClear,
        A64Insn::MsrImmMsrSiPstate { crm: 1 } => Form::PanSet,
        A64Insn::MsrImmMsrSiPstate { .. } => Form::MsrOther,

        A64Insn::LdrImmGenLdr32LdstImmpost { mem, .. }
        | A64Insn::LdrImmGenLdr32LdstImmpre { mem, .. }
        | A64Insn::LdrImmGenLdr32LdstPos { mem, .. } => runtime(mem, 4, false),
        A64Insn::LdrImmGenLdr64LdstImmpost { mem, .. }
        | A64Insn::LdrImmGenLdr64LdstImmpre { mem, .. }
        | A64Insn::LdrImmGenLdr64LdstPos { mem, .. } => runtime(mem, 8, false),
        A64Insn::StrImmGenStr32LdstImmpost { mem, .. }
        | A64Insn::StrImmGenStr32LdstImmpre { mem, .. }
        | A64Insn::StrImmGenStr32LdstPos { mem, .. } => runtime(mem, 4, true),
        A64Insn::StrImmGenStr64LdstImmpost { mem, .. }
        | A64Insn::StrImmGenStr64LdstImmpre { mem, .. }
        | A64Insn::StrImmGenStr64LdstPos { mem, .. } => runtime(mem, 8, true),
        A64Insn::LdpGenLdp64LdstpairPost { mem, .. }
        | A64Insn::LdpGenLdp64LdstpairPre { mem, .. }
        | A64Insn::LdpGenLdp64LdstpairOff { mem, .. } => runtime(mem, 16, false),
        A64Insn::StpGenStp64LdstpairPost { mem, .. }
        | A64Insn::StpGenStp64LdstpairPre { mem, .. }
        | A64Insn::StpGenStp64LdstpairOff { mem, .. } => runtime(mem, 16, true),

        A64Insn::BUncondBOnlyBranchImm { imm26 } => Form::Branch {
            delta: imm26.value(),
            conditional: false,
        },
        A64Insn::BCondBOnlyCondbranch { imm19, .. }
        | A64Insn::CbzCbz32Compbranch { imm19, .. }
        | A64Insn::CbzCbz64Compbranch { imm19, .. }
        | A64Insn::CbnzCbnz32Compbranch { imm19, .. }
        | A64Insn::CbnzCbnz64Compbranch { imm19, .. } => Form::Branch {
            delta: imm19.value(),
            conditional: true,
        },
        A64Insn::TbzTbzOnlyTestbranch { imm14, .. }
        | A64Insn::TbnzTbnzOnlyTestbranch { imm14, .. } => Form::Branch {
            delta: imm14.value(),
            conditional: true,
        },

        A64Insn::BlBlOnlyBranchImm { .. } => Form::Call,
        A64Insn::BrBr64BranchReg { .. }
        | A64Insn::BlrBlr64BranchReg { .. }
        | A64Insn::RetRet64rBranchReg { .. } => Form::IndirectBranch,
        A64Insn::SvcSvcExException { .. } => Form::Exception,
        A64Insn::AdrAdrOnlyPcreladdr { .. } | A64Insn::AdrpAdrpOnlyPcreladdr { .. } => {
            Form::PcRelative
        }
        A64Insn::MrsMrsRsSystemmove { .. } => Form::MrsTpidrEl0,
        A64Insn::NopNopHiHints {} => Form::Nop,
        A64Insn::DmbDmbBoBarriers { .. }
        | A64Insn::DsbDsbBoBarriers { .. }
        | A64Insn::IsbIsbBiBarriers { .. } => Form::Barrier,

        A64Insn::AddAddsubImmAdd32AddsubImm { .. }
        | A64Insn::AddAddsubImmAdd64AddsubImm { .. }
        | A64Insn::SubAddsubImmSub32AddsubImm { .. }
        | A64Insn::SubAddsubImmSub64AddsubImm { .. }
        | A64Insn::SubsAddsubImmSubs32sAddsubImm { .. }
        | A64Insn::SubsAddsubImmSubs64sAddsubImm { .. }
        | A64Insn::AddsAddsubImmAdds32sAddsubImm { .. }
        | A64Insn::AddsAddsubImmAdds64sAddsubImm { .. }
        | A64Insn::AddAddsubShiftAdd32AddsubShift { .. }
        | A64Insn::AddAddsubShiftAdd64AddsubShift { .. }
        | A64Insn::AddsAddsubShiftAdds32AddsubShift { .. }
        | A64Insn::AddsAddsubShiftAdds64AddsubShift { .. }
        | A64Insn::SubAddsubShiftSub32AddsubShift { .. }
        | A64Insn::SubAddsubShiftSub64AddsubShift { .. }
        | A64Insn::SubsAddsubShiftSubs32AddsubShift { .. }
        | A64Insn::SubsAddsubShiftSubs64AddsubShift { .. }
        | A64Insn::AddAddsubExtAdd32AddsubExt { .. }
        | A64Insn::AddAddsubExtAdd64AddsubExt { .. }
        | A64Insn::AddsAddsubExtAdds32sAddsubExt { .. }
        | A64Insn::AddsAddsubExtAdds64sAddsubExt { .. }
        | A64Insn::SubAddsubExtSub32AddsubExt { .. }
        | A64Insn::SubAddsubExtSub64AddsubExt { .. }
        | A64Insn::SubsAddsubExtSubs32sAddsubExt { .. }
        | A64Insn::SubsAddsubExtSubs64sAddsubExt { .. }
        | A64Insn::MovzMovz32Movewide { .. }
        | A64Insn::MovzMovz64Movewide { .. }
        | A64Insn::MovkMovk32Movewide { .. }
        | A64Insn::MovkMovk64Movewide { .. }
        | A64Insn::MovnMovn32Movewide { .. }
        | A64Insn::MovnMovn64Movewide { .. }
        | A64Insn::AndLogShiftAnd32LogShift { .. }
        | A64Insn::AndLogShiftAnd64LogShift { .. }
        | A64Insn::AndsLogShiftAnds32LogShift { .. }
        | A64Insn::AndsLogShiftAnds64LogShift { .. }
        | A64Insn::OrrLogShiftOrr32LogShift { .. }
        | A64Insn::OrrLogShiftOrr64LogShift { .. }
        | A64Insn::EorLogShiftEor32LogShift { .. }
        | A64Insn::EorLogShiftEor64LogShift { .. }
        | A64Insn::EonEon32LogShift { .. }
        | A64Insn::EonEon64LogShift { .. }
        | A64Insn::BicLogShiftBic32LogShift { .. }
        | A64Insn::BicLogShiftBic64LogShift { .. }
        | A64Insn::BicsBics32LogShift { .. }
        | A64Insn::BicsBics64LogShift { .. }
        | A64Insn::OrnLogShiftOrn32LogShift { .. }
        | A64Insn::OrnLogShiftOrn64LogShift { .. }
        | A64Insn::AndLogImmAnd32LogImm { .. }
        | A64Insn::AndLogImmAnd64LogImm { .. }
        | A64Insn::AndsLogImmAnds32sLogImm { .. }
        | A64Insn::AndsLogImmAnds64sLogImm { .. }
        | A64Insn::OrrLogImmOrr32LogImm { .. }
        | A64Insn::OrrLogImmOrr64LogImm { .. }
        | A64Insn::EorLogImmEor32LogImm { .. }
        | A64Insn::EorLogImmEor64LogImm { .. }
        | A64Insn::SbfmSbfm32mBitfield { .. }
        | A64Insn::SbfmSbfm64mBitfield { .. }
        | A64Insn::UbfmUbfm32mBitfield { .. }
        | A64Insn::UbfmUbfm64mBitfield { .. }
        | A64Insn::BfmBfm32mBitfield { .. }
        | A64Insn::BfmBfm64mBitfield { .. }
        | A64Insn::ExtrExtr32Extract { .. }
        | A64Insn::ExtrExtr64Extract { .. }
        | A64Insn::CselCsel32Condsel { .. }
        | A64Insn::CselCsel64Condsel { .. }
        | A64Insn::CsincCsinc32Condsel { .. }
        | A64Insn::CsincCsinc64Condsel { .. }
        | A64Insn::CsinvCsinv32Condsel { .. }
        | A64Insn::CsinvCsinv64Condsel { .. }
        | A64Insn::CsnegCsneg32Condsel { .. }
        | A64Insn::CsnegCsneg64Condsel { .. }
        | A64Insn::CcmpImmCcmp32CondcmpImm { .. }
        | A64Insn::CcmpImmCcmp64CondcmpImm { .. }
        | A64Insn::CcmpRegCcmp32CondcmpReg { .. }
        | A64Insn::CcmpRegCcmp64CondcmpReg { .. }
        | A64Insn::CcmnImmCcmn32CondcmpImm { .. }
        | A64Insn::CcmnImmCcmn64CondcmpImm { .. }
        | A64Insn::CcmnRegCcmn32CondcmpReg { .. }
        | A64Insn::CcmnRegCcmn64CondcmpReg { .. }
        | A64Insn::LslvLslv32Dp2src { .. }
        | A64Insn::LslvLslv64Dp2src { .. }
        | A64Insn::LsrvLsrv32Dp2src { .. }
        | A64Insn::LsrvLsrv64Dp2src { .. }
        | A64Insn::AsrvAsrv32Dp2src { .. }
        | A64Insn::AsrvAsrv64Dp2src { .. }
        | A64Insn::RorvRorv32Dp2src { .. }
        | A64Insn::RorvRorv64Dp2src { .. }
        | A64Insn::UdivUdiv32Dp2src { .. }
        | A64Insn::UdivUdiv64Dp2src { .. }
        | A64Insn::SdivSdiv32Dp2src { .. }
        | A64Insn::SdivSdiv64Dp2src { .. }
        | A64Insn::MaddMadd32aDp3src { .. }
        | A64Insn::MaddMadd64aDp3src { .. }
        | A64Insn::MsubMsub32aDp3src { .. }
        | A64Insn::MsubMsub64aDp3src { .. }
        | A64Insn::SmaddlSmaddl64waDp3src { .. }
        | A64Insn::UmaddlUmaddl64waDp3src { .. }
        | A64Insn::SmulhSmulh64Dp3src { .. }
        | A64Insn::UmulhUmulh64Dp3src { .. }
        | A64Insn::ClzIntClz32Dp1src { .. }
        | A64Insn::ClzIntClz64Dp1src { .. }
        | A64Insn::RbitIntRbit32Dp1src { .. }
        | A64Insn::RbitIntRbit64Dp1src { .. }
        | A64Insn::RevRev32Dp1src { .. }
        | A64Insn::RevRev64Dp1src { .. }
        | A64Insn::Rev16IntRev1632Dp1src { .. }
        | A64Insn::Rev16IntRev1664Dp1src { .. }
        | A64Insn::Rev32IntRev3264Dp1src { .. }
        // A7d: carry arithmetic (reads NZCV.C), multiply-subtract long, CRC32*.
        | A64Insn::AdcAdc32AddsubCarry { .. }
        | A64Insn::AdcAdc64AddsubCarry { .. }
        | A64Insn::AdcsAdcs32AddsubCarry { .. }
        | A64Insn::AdcsAdcs64AddsubCarry { .. }
        | A64Insn::SbcSbc32AddsubCarry { .. }
        | A64Insn::SbcSbc64AddsubCarry { .. }
        | A64Insn::SbcsSbcs32AddsubCarry { .. }
        | A64Insn::SbcsSbcs64AddsubCarry { .. }
        | A64Insn::SmsublSmsubl64waDp3src { .. }
        | A64Insn::UmsublUmsubl64waDp3src { .. }
        | A64Insn::Crc32Crc32b32cDp2src { .. }
        | A64Insn::Crc32Crc32h32cDp2src { .. }
        | A64Insn::Crc32Crc32w32cDp2src { .. }
        | A64Insn::Crc32Crc32x64cDp2src { .. }
        | A64Insn::Crc32cCrc32cb32cDp2src { .. }
        | A64Insn::Crc32cCrc32ch32cDp2src { .. }
        | A64Insn::Crc32cCrc32cw32cDp2src { .. }
        | A64Insn::Crc32cCrc32cx64cDp2src { .. } => Form::Alu,
    }
}

const fn runtime(mem: A64Mem, bytes: u32, store: bool) -> Form {
    Form::RuntimeAccess { mem, bytes, store }
}

/// Registers an instruction writes, from the generated operand roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Writes {
    /// Bit n set: x_n / w_n (n < 31) is written.
    pub(super) gprs: u32,
    /// Register 31 in its SP meaning (or an unknown reg31 mode) is written,
    /// including base writeback of `[sp, #imm]!` / `[sp], #imm`.
    pub(super) sp: bool,
}

/// `None` when the generated metadata names a register field the form cannot
/// return: fail closed, the caller rejects the word.
pub(super) fn writes(insn: &A64Insn) -> Option<Writes> {
    let mut out = Writes { gprs: 0, sp: false };
    for role in insn.operand_roles() {
        let reg = match *role {
            A64OperandRole::RegWrite { field, .. } | A64OperandRole::RegReadWrite { field, .. } => {
                insn.get_reg(field)?
            }
            A64OperandRole::ImplicitRegWrite { reg, .. } => A64Reg::x(reg),
            _ => continue,
        };
        if reg.enc() < 31 {
            out.gprs |= 1 << reg.enc();
        } else if reg.reg31 != A64Reg31Mode::Xzr {
            out.sp = true;
        }
    }
    Some(out)
}

/// Registers an instruction reads, from the generated operand roles. The memory
/// base is kept apart from the data operands: rule 9 lets a kernel value be a base
/// (of an allowed runtime access) and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Reads {
    /// Bit n set: x_n / w_n (n < 31) is read as data (store data, ALU source,
    /// branch operand, `MOVK`/`BFM` destination, atomic operand).
    pub(super) gprs: u32,
    /// Register 31 in its SP meaning (or an unknown reg31 mode) is read as data.
    pub(super) sp: bool,
    /// The memory base register, if the form has one.
    pub(super) base: Option<A64Reg>,
}

/// `None` when the generated metadata names a register field the form cannot
/// return: fail closed, the caller rejects the word.
pub(super) fn reads(insn: &A64Insn) -> Option<Reads> {
    let base_field = insn.operand_roles().iter().find_map(|role| match *role {
        A64OperandRole::MemBase { field } => Some(field),
        _ => None,
    });
    let mut out = Reads {
        gprs: 0,
        sp: false,
        base: None,
    };
    for role in insn.operand_roles() {
        let field = match *role {
            A64OperandRole::RegRead { field, .. } | A64OperandRole::RegReadWrite { field, .. } => {
                field
            }
            _ => continue,
        };
        let reg = insn.get_reg(field)?;
        if Some(field) == base_field {
            out.base = Some(reg);
        } else if reg.enc() < 31 {
            out.gprs |= 1 << reg.enc();
        } else if reg.reg31 != A64Reg31Mode::Xzr {
            out.sp = true;
        }
    }
    Some(out)
}

pub(super) const fn is_sp(reg: A64Reg) -> bool {
    reg.enc() == 31 && !matches!(reg.reg31, A64Reg31Mode::Xzr)
}

/// Kernel frame pointer. The prologue sets it to the runtime frame and the body
/// never writes it (user x29 lives in x16), so an unwinder that interrupts a
/// fragment still follows a valid frame record.
pub(super) const KERNEL_FP_REG: u8 = 29;

// Runtime frame windows (shared/abi/frame.rs layout). The body may only touch the
// user-state slots: stack-backed x12..x17, then user x29 and user sp, ending where
// the entry-address slot starts. Everything else in the frame (caller x29/x30, the
// entry address, caller x18..x28, the pt_regs / extra-params pointers) is kernel
// state the epilogue trusts: a body write there is a kernel write primitive (the
// epilogue's `ret`, callee-saved registers, or the pt_regs store target).
pub(super) const FRAME_USER_START: u32 =
    match reg_virt_stack_backed_slot_offset(REG_VIRT_STACK_BACKED_REG_START) {
        Some(offset) => offset,
        None => panic!("stack-backed range has a first slot"),
    };
pub(super) const FRAME_USER_END: u32 = RUNTIME_FRAME_ENTRY_ADDR_OFFSET;

/// The one kernel-frame read the body may do: `ldr xS, [sp, #PT_REGS_PTR]`
/// (64-bit, offset form) with S a reg-virt scratch register, which makes xS a
/// pt_regs pointer for the dataflow in `taint.rs`. Scratch only: the epilogue
/// never writes scratch back to the user, and a kernel pointer in a user register
/// is one edge away from `pt_regs` (rule 9). Returns S.
pub(super) fn pt_regs_pointer_load(insn: &A64Insn) -> Option<u8> {
    match insn {
        A64Insn::LdrImmGenLdr64LdstPos {
            rt,
            mem: A64Mem::Offset { base, offset },
        } if is_sp(*base)
            && offset.value() == RUNTIME_FRAME_PT_REGS_PTR_OFFSET as i64
            && (REG_VIRT_SCRATCH_GPR_START..=REG_VIRT_SCRATCH_GPR_END).contains(&rt.enc()) =>
        {
            Some(rt.enc())
        }
        _ => None,
    }
}

/// `pt_regs` bytes the body may access: `regs[0..31]` and `sp`. `pc`, `pstate` and
/// everything after them are never fragment-accessible (a `pstate` write would
/// return to userspace at EL1).
pub(super) const PT_REGS_USER_STATE_END: u32 = match pt_regs_x_slot_offset(30) {
    Some(offset) => offset + 16,
    None => panic!("pt_regs has an x30 slot"),
};

// Execution budget (A6, tmp/pipeline.md "Execution budget (A6)"). Before every
// back-edge: `ldr s, [sp, #slot]; sub s, s, #1; str s, [sp, #slot]; cbz s, <stub>`,
// then only reg-virt fill loads, then the branch. The counter slot is written by
// the prologue (byte-exact) and by this sequence, nothing else.
pub(super) const BUDGET_SLOT_OFFSET: u32 = RUNTIME_FRAME_BUDGET_OFFSET;
/// The check's scratch: the first reg-virt scratch register, as in the prologue's
/// budget init (dead at every instruction boundary).
pub(super) const BUDGET_SCRATCH_REG: u8 = REG_VIRT_SCRATCH_GPR_START;

/// A reg-virt fill that may sit between the budget `cbz` and its back-edge:
/// `ldr x<scratch>, [sp, #<stack-backed slot>]` (64-bit, offset form).
pub(super) fn is_budget_fill(insn: &A64Insn) -> bool {
    let (Some(first), Some(last)) = (
        reg_virt_stack_backed_slot_offset(REG_VIRT_STACK_BACKED_REG_START),
        reg_virt_stack_backed_slot_offset(REG_VIRT_STACK_BACKED_REG_END),
    ) else {
        return false;
    };
    matches!(insn, A64Insn::LdrImmGenLdr64LdstPos { rt, mem: A64Mem::Offset { base, offset } }
        if (REG_VIRT_SCRATCH_GPR_START..=REG_VIRT_SCRATCH_GPR_END).contains(&rt.enc())
            && is_sp(*base)
            && offset.value() >= first as i64
            && offset.value() <= last as i64)
}

/// `ldr s, [sp, #slot]`, `sub s, s, #1`, `str s, [sp, #slot]`, `cbz s, <label>`
/// (64-bit forms). Returns the `cbz` byte delta.
pub(super) fn budget_sequence(seq: &[A64Insn]) -> Option<i64> {
    let [ldr, sub, str, cbz] = seq else {
        return None;
    };
    let s = BUDGET_SCRATCH_REG;
    let slot = |mem: &A64Mem| {
        matches!(mem, A64Mem::Offset { base, offset }
            if is_sp(*base) && offset.value() == BUDGET_SLOT_OFFSET as i64)
    };
    let ldr_ok =
        matches!(ldr, A64Insn::LdrImmGenLdr64LdstPos { rt, mem } if rt.enc() == s && slot(mem));
    let sub_ok = matches!(sub, A64Insn::SubAddsubImmSub64AddsubImm { sh: 0, imm12, rn, rd }
        if imm12.value() == 1 && rn.enc() == s && rd.enc() == s);
    let str_ok =
        matches!(str, A64Insn::StrImmGenStr64LdstPos { rt, mem } if rt.enc() == s && slot(mem));
    match cbz {
        A64Insn::CbzCbz64Compbranch { imm19, rt }
            if ldr_ok && sub_ok && str_ok && rt.enc() == s =>
        {
            Some(imm19.value())
        }
        _ => None,
    }
}

/// The PAN window's range check (A8): `ubfx sB, sA, #USER_VA_BITS, #width` with
/// `width` reaching bit `PAN_WINDOW_RANGE_TOP_BIT` (64-bit `UBFM`, `immr = 48`,
/// `imms = 55`), both registers general-purpose. Returns `(sA, sB)`.
pub(super) fn range_check(insn: &A64Insn) -> Option<(u8, u8)> {
    match insn {
        A64Insn::UbfmUbfm64mBitfield { immr, imms, rn, rd }
            if immr.value() == USER_VA_BITS as i64
                && imms.value() == PAN_WINDOW_RANGE_TOP_BIT as i64
                && rn.enc() < 31
                && rd.enc() < 31 =>
        {
            Some((rn.enc(), rd.enc()))
        }
        _ => None,
    }
}

/// `cbnz x<reg>, <label>` (64-bit): returns `(reg, byte delta)`.
pub(super) fn cbnz64(insn: &A64Insn) -> Option<(u8, i64)> {
    match insn {
        A64Insn::CbnzCbnz64Compbranch { imm19, rt } => Some((rt.enc(), imm19.value())),
        _ => None,
    }
}
