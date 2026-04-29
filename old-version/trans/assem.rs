pub(crate) mod prelude {
	pub(crate) use super::{*, Cond, Reg, SysReg, MemAccCls, ShiftCls, TInsn::*, check_mem_acc_cls};
}

use super::*;
use crate::utils;
pub(crate) use super::SysReg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) enum Reg {
	X(u8),
	W(u8),
	B(u8),
	D(u8),
	Q(u8),
	H(u8),
	P(u8),
	S(u8),
	V(u8),
	SP,
	INV,
}

impl Reg {
	pub(crate) fn to_x_reg(self) -> Self {
		match self {
			Reg::W(w_reg) => {
				Reg::X(w_reg)
			}
			_ => {
				self
			}
		}
	}

	pub(crate) fn to_w_reg(self) -> Self {
		match self {
			Reg::X(x_reg) => {
				Reg::W(x_reg)
			}
			_ => {
				self
			}
		}
	}
}

// Implemented such that SP and X31/XZR will be mapped to the same 5 bits and Xn, Wn will have the same mapping, used in mod `assem`
impl From<Reg> for u32 {
	fn from(value: Reg) -> Self {
	    match value {
	    	Reg::X(x_reg) => {
	    		match x_reg {
	    			gpr @ 0..=31 => { gpr as u32 }
	    			_ => {
	    				pr_err!("Incorrect r_reg value, defaulting to w0\n");
	    				0b0_0000_u32
	    			}
	    		}
	    	}
	    	Reg::W(w_reg) => {
	    		match w_reg {
	    			gpr @ 0..=31 => { gpr as u32 }
	    			_ => {
	    				pr_err!("Incorrect w_reg value, defaulting to w0\n");
	    				0b0_0000_u32
	    			}
	    		}
	    	}
	    	Reg::D(d_reg) => {
	    		match d_reg {
	    			gpr @ 0..=31 => { gpr as u32 }
	    			_ => {
	    				pr_err!("Incorrect d_reg value, defaulting to w0\n");
	    				0b0_0000_u32
	    			}
	    		}
	    	}
	    	Reg::Q(q_reg) => {
	    		match q_reg {
	    			gpr @ 0..=31 => { gpr as u32 }
	    			_ => {
	    				pr_err!("Incorrect q_reg value, defaulting to w0\n");
	    				0b0_0000_u32
	    			}
	    		}
	    	}
	    	Reg::SP => {
	    		0b1_1111_u32
	    	}
	    	Reg::INV => {
	    		pr_err!("Invalid Reg value, defaulting to x0\n");
	    		0b0_0000_u32
	    	}
	    	_ => {
	    		unimplemented!("{:?} assem\n", value);
	    	}
	    }
	}
}

// For interaction with Capstone
impl From<u32> for Reg {
	fn from(value: u32) -> Self {
	    match value {
	    	0   => Self::INV,
	    	// Wn
	    	187 => Self::W(0),
	    	188 => Self::W(1),
	    	189 => Self::W(2),
	    	190 => Self::W(3),
	    	191 => Self::W(4),
	    	192 => Self::W(5),
	    	193 => Self::W(6),
	    	194 => Self::W(7),
	    	195 => Self::W(8),
	    	196 => Self::W(9),
	    	197 => Self::W(10),
	    	198 => Self::W(11),
	    	199 => Self::W(12),
	    	200 => Self::W(13),
	    	201 => Self::W(14),
	    	202 => Self::W(15),
	    	203 => Self::W(16),
	    	204 => Self::W(17),
	    	205 => Self::W(18),
	    	206 => Self::W(19),
	    	207 => Self::W(20),
	    	208 => Self::W(21),
	    	209 => Self::W(22),
	    	210 => Self::W(23),
	    	211 => Self::W(24),
	    	212 => Self::W(25),
	    	213 => Self::W(26),
	    	214 => Self::W(27),
	    	215 => Self::W(28),
	    	216 => Self::W(29),
	    	217 => Self::W(30),
	    	8   => Self::W(31),
	    	// Xn
	    	218 => Self::X(0),
	    	219 => Self::X(1),
	    	220 => Self::X(2),
	    	221 => Self::X(3),
	    	222 => Self::X(4),
	    	223 => Self::X(5),
	    	224 => Self::X(6),
	    	225 => Self::X(7),
	    	226 => Self::X(8),
	    	227 => Self::X(9),
	    	228 => Self::X(10),
	    	229 => Self::X(11),
	    	230 => Self::X(12),
	    	231 => Self::X(13),
	    	232 => Self::X(14),
	    	233 => Self::X(15),
	    	234 => Self::X(16),
	    	235 => Self::X(17),
	    	236 => Self::X(18),
	    	237 => Self::X(19),
	    	238 => Self::X(20),
	    	239 => Self::X(21),
	    	240 => Self::X(22),
	    	241 => Self::X(23),
	    	242 => Self::X(24),
	    	243 => Self::X(25),
	    	244 => Self::X(26),
	    	245 => Self::X(27),
	    	246 => Self::X(28),
	    	2   => Self::X(29),
	    	3   => Self::X(30),
	    	9   => Self::X(31),
	    	// Bn
	    	11 => Self::B(0),
	    	12 => Self::B(1),
	    	13 => Self::B(2),
	    	14 => Self::B(3),
	    	15 => Self::B(4),
	    	16 => Self::B(5),
	    	17 => Self::B(6),
	    	18 => Self::B(7),
	    	19 => Self::B(8),
	    	20 => Self::B(9),
	    	21 => Self::B(10),
	    	22 => Self::B(11),
	    	23 => Self::B(12),
	    	24 => Self::B(13),
	    	25 => Self::B(14),
	    	26 => Self::B(15),
	    	27 => Self::B(16),
	    	28 => Self::B(17),
	    	29 => Self::B(18),
	    	30 => Self::B(19),
	    	31 => Self::B(20),
	    	32 => Self::B(21),
	    	33 => Self::B(22),
	    	34 => Self::B(23),
	    	35 => Self::B(24),
	    	36 => Self::B(25),
	    	37 => Self::B(26),
	    	38 => Self::B(27),
	    	39 => Self::B(28),
	    	40 => Self::B(29),
	    	41 => Self::B(30),
	    	42 => Self::B(31),
	    	// Dn
	    	43 => Self::D(0),
	    	44 => Self::D(1),
	    	45 => Self::D(2),
	    	46 => Self::D(3),
	    	47 => Self::D(4),
	    	48 => Self::D(5),
	    	49 => Self::D(6),
	    	50 => Self::D(7),
	    	51 => Self::D(8),
	    	52 => Self::D(9),
	    	53 => Self::D(10),
	    	54 => Self::D(11),
	    	55 => Self::D(12),
	    	56 => Self::D(13),
	    	57 => Self::D(14),
	    	58 => Self::D(15),
	    	59 => Self::D(16),
	    	60 => Self::D(17),
	    	61 => Self::D(18),
	    	62 => Self::D(19),
	    	63 => Self::D(20),
	    	64 => Self::D(21),
	    	65 => Self::D(22),
	    	66 => Self::D(23),
	    	67 => Self::D(24),
	    	68 => Self::D(25),
	    	69 => Self::D(26),
	    	70 => Self::D(27),
	    	71 => Self::D(28),
	    	72 => Self::D(29),
	    	73 => Self::D(30),
	    	74 => Self::D(31),
	    	// Hn
	    	75 => Self::H(0),
	    	76 => Self::H(1),
	    	77 => Self::H(2),
	    	78 => Self::H(3),
	    	79 => Self::H(4),
	    	80 => Self::H(5),
	    	81 => Self::H(6),
	    	82 => Self::H(7),
	    	83 => Self::H(8),
	    	84 => Self::H(9),
	    	85 => Self::H(10),
	    	86 => Self::H(11),
	    	87 => Self::H(12),
	    	88 => Self::H(13),
	    	89 => Self::H(14),
	    	90 => Self::H(15),
	    	91 => Self::H(16),
	    	92 => Self::H(17),
	    	93 => Self::H(18),
	    	94 => Self::H(19),
	    	95 => Self::H(20),
	    	96 => Self::H(21),
	    	97 => Self::H(22),
	    	98 => Self::H(23),
	    	99 => Self::H(24),
	    	100 => Self::H(25),
	    	101 => Self::H(26),
	    	102 => Self::H(27),
	    	103 => Self::H(28),
	    	104 => Self::H(29),
	    	105 => Self::H(30),
	    	106 => Self::H(31),
	    	// Pn
	    	107 => Self::P(0),
	    	108 => Self::P(1),
	    	109 => Self::P(2),
	    	110 => Self::P(3),
	    	111 => Self::P(4),
	    	112 => Self::P(5),
	    	113 => Self::P(6),
	    	114 => Self::P(7),
	    	115 => Self::P(8),
	    	116 => Self::P(9),
	    	117 => Self::P(10),
	    	118 => Self::P(11),
	    	119 => Self::P(12),
	    	120 => Self::P(13),
	    	121 => Self::P(14),
	    	122 => Self::P(15),
	    	// Qn
	    	123 => Self::Q(0),
	    	124 => Self::Q(1),
	    	125 => Self::Q(2),
	    	126 => Self::Q(3),
	    	127 => Self::Q(4),
	    	128 => Self::Q(5),
	    	129 => Self::Q(6),
	    	130 => Self::Q(7),
	    	131 => Self::Q(8),
	    	132 => Self::Q(9),
	    	133 => Self::Q(10),
	    	134 => Self::Q(11),
	    	135 => Self::Q(12),
	    	136 => Self::Q(13),
	    	137 => Self::Q(14),
	    	138 => Self::Q(15),
	    	139 => Self::Q(16),
	    	140 => Self::Q(17),
	    	141 => Self::Q(18),
	    	142 => Self::Q(19),
	    	143 => Self::Q(20),
	    	144 => Self::Q(21),
	    	145 => Self::Q(22),
	    	146 => Self::Q(23),
	    	147 => Self::Q(24),
	    	148 => Self::Q(25),
	    	149 => Self::Q(26),
	    	150 => Self::Q(27),
	    	151 => Self::Q(28),
	    	152 => Self::Q(29),
	    	153 => Self::Q(30),
	    	154 => Self::Q(31),
	    	// Sn
	    	155 => Self::S(0),
	    	156 => Self::S(1),
	    	157 => Self::S(2),
	    	158 => Self::S(3),
	    	159 => Self::S(4),
	    	160 => Self::S(5),
	    	161 => Self::S(6),
	    	162 => Self::S(7),
	    	163 => Self::S(8),
	    	164 => Self::S(9),
	    	165 => Self::S(10),
	    	166 => Self::S(11),
	    	167 => Self::S(12),
	    	168 => Self::S(13),
	    	169 => Self::S(14),
	    	170 => Self::S(15),
	    	171 => Self::S(16),
	    	172 => Self::S(17),
	    	173 => Self::S(18),
	    	174 => Self::S(19),
	    	175 => Self::S(20),
	    	176 => Self::S(21),
	    	177 => Self::S(22),
	    	178 => Self::S(23),
	    	179 => Self::S(24),
	    	180 => Self::S(25),
	    	181 => Self::S(26),
	    	182 => Self::S(27),
	    	183 => Self::S(28),
	    	184 => Self::S(29),
	    	185 => Self::S(30),
	    	186 => Self::S(31),
	    	// Vn
	    	310 => Self::V(0),
	    	311 => Self::V(1),
	    	312 => Self::V(2),
	    	313 => Self::V(3),
	    	314 => Self::V(4),
	    	315 => Self::V(5),
	    	316 => Self::V(6),
	    	317 => Self::V(7),
	    	318 => Self::V(8),
	    	319 => Self::V(9),
	    	320 => Self::V(10),
	    	321 => Self::V(11),
	    	322 => Self::V(12),
	    	323 => Self::V(13),
	    	324 => Self::V(14),
	    	325 => Self::V(15),
	    	326 => Self::V(16),
	    	327 => Self::V(17),
	    	328 => Self::V(18),
	    	329 => Self::V(19),
	    	330 => Self::V(20),
	    	331 => Self::V(21),
	    	332 => Self::V(22),
	    	333 => Self::V(23),
	    	334 => Self::V(24),
	    	335 => Self::V(25),
	    	336 => Self::V(26),
	    	337 => Self::V(27),
	    	338 => Self::V(28),
	    	339 => Self::V(29),
	    	340 => Self::V(30),
	    	341 => Self::V(31),
	    	// Special regs
	    	5   => Self::SP,
	    	_ => {
	    		pr_warn!("Unsupported Reg val {}\n", value);
	    		Self::INV
	    	}
	    }
	}
}

impl From<u8> for Reg {
	fn from(value: u8) -> Self {
	    match value {
	    	0  => Self::X(0),
	    	1  => Self::X(1),
	    	2  => Self::X(2),
	    	3  => Self::X(3),
	    	4  => Self::X(4),
	    	5  => Self::X(5),
	    	6  => Self::X(6),
	    	7  => Self::X(7),
	    	8  => Self::X(8),
	    	9  => Self::X(9),
	    	10 => Self::X(10),
	    	11 => Self::X(11),
	    	12 => Self::X(12),
	    	13 => Self::X(13),
	    	14 => Self::X(14),
	    	15 => Self::X(15),
	    	16 => Self::X(16),
	    	17 => Self::X(17),
	    	18 => Self::X(18),
	    	19 => Self::X(19),
	    	20 => Self::X(20),
	    	21 => Self::X(21),
	    	22 => Self::X(22),
	    	23 => Self::X(23),
	    	24 => Self::X(24),
	    	25 => Self::X(25),
	    	26 => Self::X(26),
	    	27 => Self::X(27),
	    	28 => Self::X(28),
	    	29 => Self::X(29),
	    	30 => Self::X(30),
	    	31 => Self::X(31),
	    	32 => Self::SP,
	    	_  => Self::INV,
	    }
	}
}

// For interaction with UCA runtime
impl From<Reg> for u64 {
	fn from(value: Reg) -> Self {
	    match value {
	    	Reg::INV => 0b0,
	    	Reg::X(0)  | Reg::W(0)  => 0b1 << 0,
	    	Reg::X(1)  | Reg::W(1)  => 0b1 << 1,
	    	Reg::X(2)  | Reg::W(2)  => 0b1 << 2,
	    	Reg::X(3)  | Reg::W(3)  => 0b1 << 3,
	    	Reg::X(4)  | Reg::W(4)  => 0b1 << 4,
	    	Reg::X(5)  | Reg::W(5)  => 0b1 << 5,
	    	Reg::X(6)  | Reg::W(6)  => 0b1 << 6,
	    	Reg::X(7)  | Reg::W(7)  => 0b1 << 7,
	    	Reg::X(8)  | Reg::W(8)  => 0b1 << 8,
	    	Reg::X(9)  | Reg::W(9)  => 0b1 << 9,
	    	Reg::X(10) | Reg::W(10) => 0b1 << 10,
	    	Reg::X(11) | Reg::W(11) => 0b1 << 11,
	    	Reg::X(12) | Reg::W(12) => 0b1 << 12,
	    	Reg::X(13) | Reg::W(13) => 0b1 << 13,
	    	Reg::X(14) | Reg::W(14) => 0b1 << 14,
	    	Reg::X(15) | Reg::W(15) => 0b1 << 15,
	    	Reg::X(16) | Reg::W(16) => 0b1 << 16,
	    	Reg::X(17) | Reg::W(17) => 0b1 << 17,
	    	Reg::X(18) | Reg::W(18) => 0b1 << 18,
	    	Reg::X(19) | Reg::W(19) => 0b1 << 19,
	    	Reg::X(20) | Reg::W(20) => 0b1 << 20,
	    	Reg::X(21) | Reg::W(21) => 0b1 << 21,
	    	Reg::X(22) | Reg::W(22) => 0b1 << 22,
	    	Reg::X(23) | Reg::W(23) => 0b1 << 23,
	    	Reg::X(24) | Reg::W(24) => 0b1 << 24,
	    	Reg::X(25) | Reg::W(25) => 0b1 << 25,
	    	Reg::X(26) | Reg::W(26) => 0b1 << 26,
	    	Reg::X(27) | Reg::W(27) => 0b1 << 27,
	    	Reg::X(28) | Reg::W(28) => 0b1 << 28,
	    	Reg::X(29) | Reg::W(29) => 0b1 << 29,
	    	Reg::X(30) | Reg::W(30) => 0b1 << 30,
	    	Reg::X(31) | Reg::W(31) => 0b1 << 31,
	    	Reg::SP  => 0b1 << 32,
	    	_ => {
	    		// pr_err!("Incorrect Reg, treated as Reg::INV\n");
	    		// We don't care about other registers yet.
	    		0b0
	    	}
	    }
	}
}

impl From<u64> for Reg {
	fn from(value: u64) -> Self {
	    match value {
	    	1          => Self::X(0),
	    	2          => Self::X(1),
	    	4          => Self::X(2),
	    	8          => Self::X(3),
	    	16         => Self::X(4),
	    	32         => Self::X(5),
	    	64         => Self::X(6),
	    	128        => Self::X(7),
	    	256        => Self::X(8),
	    	512        => Self::X(9),
	    	1024       => Self::X(10),
	    	2048       => Self::X(11),
	    	4096       => Self::X(12),
	    	8192       => Self::X(13),
	    	16384      => Self::X(14),
	    	32768      => Self::X(15),
	    	65536      => Self::X(16),
	    	131072     => Self::X(17),
	    	262144     => Self::X(18),
	    	524288     => Self::X(19),
	    	1048576    => Self::X(20),
	    	2097152    => Self::X(21),
	    	4194304    => Self::X(22),
	    	8388608    => Self::X(23),
	    	16777216   => Self::X(24),
	    	33554432   => Self::X(25),
	    	67108864   => Self::X(26),
	    	134217728  => Self::X(27),
	    	268435456  => Self::X(28),
	    	536870912  => Self::X(29),
	    	1073741824 => Self::X(30),
	    	2147483648 => Self::X(31),
	    	4294967296 => Self::SP,
	    	_          => Self::INV,
	    }
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) enum Cond {
	EQ = 0b0000,
	NE = 0b0001,
	CS = 0b0010,  // HS
	CC = 0b0011,  // LO
	MI = 0b0100,
	PL = 0b0101,
	VS = 0b0110,
	VC = 0b0111,
	HI = 0b1000,
	LS = 0b1001,
	GE = 0b1010,
	LT = 0b1011,
	GT = 0b1100,
	LE = 0b1101,
	AL = 0b1110,
	NV = 0b1111,
}

impl Cond {
	fn inverse(self) -> Self {
		Cond::from((self as u32) ^ 0b1)
	}
}

impl From<u32> for Cond {  /* For easy convertion from capstone arm64_cc to assem::Cond */
	fn from(value: u32) -> Self {
	    match value {
	    	1 => Self::EQ,
	    	2 => Self::NE,
	    	3 => Self::CS,
	    	4 => Self::CC,
	    	5 => Self::MI,
	    	6 => Self::PL,
	    	7 => Self::VS,
	    	8 => Self::VC,
	    	9 => Self::HI,
	    	10 => Self::LS,
	    	11 => Self::GE,
	    	12 => Self::LT,
	    	13 => Self::GT,
	    	14 => Self::LE,
	    	15 => Self::AL,
	    	16 => Self::NV,
	    	_ => Self::NV,  // Invalid, for unconditional insns
	    }
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemAccCls {
	PstIndex,
	PreIndex,
	Offset,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShiftCls {
	INV = 0b1000,
	LSL = 0b0000,
	MSL = 0b0100,
	LSR = 0b0001,
	ASR = 0b0010,
	ROR = 0b0011,
}

impl From<u32> for ShiftCls {
	fn from(value: u32) -> Self {
	    match value {
	    	0 => Self::INV,
	    	1 => Self::LSL,
	    	2 => Self::MSL,
	    	3 => Self::LSR,
	    	4 => Self::ASR,
	    	5 => Self::ROR,
	    	_ => {
	    		pr_err!("Incorrect value from u32 to ShiftCls\n");
	    		Self::INV
	    	}
	    }
	}
}

pub(crate) type Mem = (Reg, Reg, u32, MemAccCls);
pub(crate) type Shift = (ShiftCls, u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) enum TInsn {
	ADD_RRI 	(Reg, Reg, u32),
	ADD_RRR 	(Reg, Reg, Reg), 	/* Implemented as ADD (shifted register) with imm6 = 0 */
	ADDS_RRR 	(Reg, Reg, Reg), 	/* Implemented as ADDS (shifted register) with imm6 = 0 */
	ADR_RI 		(Reg, u32),   		/* Offset in number of bytes, not insns */
	ADRP_RI 	(Reg, u32),
	AND_RRR 	(Reg, Reg, Reg), 	/* Implemented as AND (shifted register) with imm6 = 0 */
	ANDS_RRRF 	(Reg, Reg, Reg, Shift),
	ANDS_RRI 	(Reg, Reg, u32),

	B_I 		(u32), 	// Holds the offset in number of bytes
	BC_IC 		(u32, Cond),
	BL_I 		(u32),
	BLR_R 		(Reg),
	BR_R 		(Reg),

	CAS_RRM 	(Reg, Reg, Mem),
	CBNZ_RI 	(Reg, u32),
	CBZ_RI 		(Reg, u32),
	CMN_RR 		(Reg, Reg),
	CMP_RI 		(Reg, u32),
	CMP_RR 		(Reg, Reg),
	CINC_RRC 	(Reg, Reg, Cond),
	CNEG_RRC 	(Reg, Reg, Cond),
	CSEL_RRRC 	(Reg, Reg, Reg, Cond),
	CSET_RC 	(Reg, Cond),
	CSINC_RRRC 	(Reg, Reg, Reg, Cond),
	CSINV_RRRC 	(Reg, Reg, Reg, Cond),
	CSNEG_RRRC 	(Reg, Reg, Reg, Cond),

	EOR_RRR 	(Reg, Reg, Reg), 	/* Implemented as EOR (shifted register) with imm6 = 0 */

	// u32 are multiplied by 2^3 before added to the offset during the real execution,
	// We try to ease our interface by dividing u32 by 2^3 before inserting the bits into the resulting insn
	// For a unified interface, we always address in granularity of byte. Consequently, non-aligned offset is automatically aligned.
	LDP_RRM 	(Reg, Reg, Mem),
	LDR_RM 		(Reg, Mem),
	LDRB_RM 	(Reg, Mem),
	LDRH_RM 	(Reg, Mem),
	LDTRB_RM 	(Reg, Mem),
	LDTRH_RM 	(Reg, Mem),
	LDUR_RM 	(Reg, Mem),
	LSL_RRR 	(Reg, Reg, Reg),
	LSR_RRR 	(Reg, Reg, Reg),

	MADD_RRRR 	(Reg, Reg, Reg, Reg),
	MOV_RI 		(Reg, u32),
	MOV_RR 		(Reg, Reg),
	MOVK_RIF 	(Reg, u32, Shift),
	MOVZ_RIF 	(Reg, u32, Shift),
	MRS_RS 		(Reg, SysReg),
	MSR_SR 		(SysReg, Reg),
	MUL_RRR 	(Reg, Reg, Reg),

	NEG_RR 		(Reg, Reg),
	NOP,

	ORR_RRR 	(Reg, Reg, Reg), 	/* Implemented as ORR (shifted register) with imm6 = 0 */

	RET_R 		(Reg),
	ROR_RRR 	(Reg, Reg, Reg),

	STLXR_RRM 	(Reg, Reg, Mem), 	/* First Reg stores the return value of this insn */
	STP_RRM 	(Reg, Reg, Mem),
	STR_RM 		(Reg, Mem),
	STRB_RM 	(Reg, Mem),
	STRH_RM 	(Reg, Mem),
	STUR_RM 	(Reg, Mem),
	STXR_RRR 	(Reg, Reg, Reg),
	SUB_RRI 	(Reg, Reg, u32),
	SUB_RRR 	(Reg, Reg, Reg),
	SUBS_RRI 	(Reg, Reg, u32), 	/* We do not support shift 12 yet */
	SUBS_RRR 	(Reg, Reg, Reg),
	SVC_I 		(u32),

	TBNZ_RII 	(Reg, u32, u32),
	TBZ_RII 	(Reg, u32, u32),
	TST_RI 		(Reg, u32),
}

/// Generates one instruction by providing this macro with the opcode, the operands, their corresponding shift values and the target `Vec` to append to.
/// 
/// For instructions beginning with operand other than R, `sf_expr` (the second field) is omitted for simplicity.
macro_rules! insn {
	// NOP
	($opcode:literal, $target:ident) => {
		{
			let opc_bytes: u32 = ($opcode);
			let insn_bytes = opc_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
	};
	// I
	($opcode:literal, $i0_expr:expr, $i0_shift:literal, $target:ident) => {
        {
			let opc_bytes: u32 = ($opcode);
			let i0_bytes: u32 = ($i0_expr) << $i0_shift;
			let insn_bytes = opc_bytes | i0_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
	// R
	($opcode:literal, $sf_expr:expr, $r0:ident, $r0_shift:literal, $target:ident) => {
        {
			let sf_bit: u32 = match $r0 {
			    Reg::W(_) => 0b0,
			    _         => ($sf_expr),
			};
			let opc_bytes: u32 = ($opcode) | sf_bit;
			let r0_bytes: u32 = u32::from($r0) << $r0_shift;
			let insn_bytes = opc_bytes | r0_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
    // IC
    ($opcode:literal, $i0_expr:expr, $i0_shift:literal, $c0:ident, $c0_shift:literal, $target:ident) => {
        {
			let opc_bytes: u32 = ($opcode);
			let i0_bytes: u32 = ($i0_expr) << $i0_shift;
			let c0_bytes: u32 = ($c0 as u32) << $c0_shift;
			let insn_bytes = opc_bytes | i0_bytes | c0_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
    // 2 operands (First one must be Reg)
    ($opcode:literal, $sf_expr:expr, $op0_expr:expr, $op0_shift:literal, $op1_expr:expr, $op1_shift:literal, $target:ident) => {
        {
			let sf_bit: u32 = match ($op0_expr) {
			    Reg::W(_) => 0b0,
			    _         => ($sf_expr),
			};
			let opc_bytes: u32 = ($opcode) | sf_bit;
			let op0_bytes: u32 = u32::from($op0_expr) << $op0_shift;
			let op1_bytes: u32 = u32::from($op1_expr) << $op1_shift;
			let insn_bytes = opc_bytes | op0_bytes | op1_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
	// 3 operands (First one must be Reg)
    ($opcode:literal, $sf_expr:expr, $op0_expr:expr, $op0_shift:literal, $op1_expr:expr, $op1_shift:literal, $op2_expr:expr, $op2_shift:literal, $target:ident) => {
        {
			let sf_bit: u32 = match ($op0_expr) {
			    Reg::W(_) => 0b0,
			    _         => ($sf_expr),
			};
			let opc_bytes: u32 = ($opcode) | sf_bit;
			let op0_bytes: u32 = u32::from($op0_expr) << $op0_shift;
			let op1_bytes: u32 = u32::from($op1_expr) << $op1_shift;
			let op2_bytes: u32 = u32::from($op2_expr) << $op2_shift;
			let insn_bytes = opc_bytes | op0_bytes | op1_bytes | op2_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
    // 4 operands (First one must be Reg)
    ($opcode:literal, $sf_expr:expr, $op0_expr:expr, $op0_shift:literal, $op1_expr:expr, $op1_shift:literal, $op2_expr:expr, $op2_shift:literal, $op3_expr:expr, $op3_shift:literal, $target:ident) => {
        {
			let sf_bit: u32 = match ($op0_expr) {
			    Reg::W(_) => 0b0,
			    _         => ($sf_expr),
			};
			let opc_bytes: u32 = ($opcode) | sf_bit;
			let op0_bytes: u32 = u32::from($op0_expr) << $op0_shift;
			let op1_bytes: u32 = u32::from($op1_expr) << $op1_shift;
			let op2_bytes: u32 = u32::from($op2_expr) << $op2_shift;
			let op3_bytes: u32 = u32::from($op3_expr) << $op3_shift;
			let insn_bytes = opc_bytes | op0_bytes | op1_bytes | op2_bytes | op3_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
    // 5 operands
    ($opcode:literal, $sf_expr:expr, $r0:ident, $r0_shift:literal, $r1:ident, $r1_shift:literal, $r2:expr, $r2_shift:literal, $i0_expr:expr, $i0_shift:literal, $i1_expr:expr, $i1_shift:literal, $target:ident) => {
        {
			let sf_bit: u32 = match ($r0) {
			    Reg::W(_) => 0b0,
			    _         => ($sf_expr),
			};
			let opc_bytes: u32 = ($opcode) | sf_bit;
			let r0_bytes: u32 = u32::from($r0) << $r0_shift;
			let r1_bytes: u32 = u32::from($r1) << $r1_shift;
			let r2_bytes: u32 = u32::from($r2) << $r2_shift;
			let i0_bytes: u32 = ($i0_expr) << $i0_shift;
			let i1_bytes: u32 = ($i1_expr) << $i1_shift;
			let insn_bytes = opc_bytes | r0_bytes | r1_bytes | r2_bytes | i0_bytes | i1_bytes;
			utils::push_insn(&mut $target, insn_bytes).unwrap();
        }
    };
}

pub(crate) fn asm(insns: &Vec<TInsn>) -> Vec<u8> {
	let mut ret = Vec::new();
	for i in 0..insns.len() {
		let insn_bytes = asm_one(insns[i]);
		for byte in insn_bytes.into_iter() {
			ret.push(byte, GFP_ATOMIC).unwrap();
		}
	}
	ret
}

pub(crate) fn asm_one(insn: TInsn) -> Vec<u8> {
	let mut ret = Vec::new();
	match insn {
		TInsn::ADD_RRI(r0, r1, i0)  		=> insn!(0b0001_0001_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, ((i0 as u32) & 0xFFF), 10, ret),
		TInsn::ADD_RRR(r0, r1, r2)  		=> insn!(0b0000_1011_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::ADDS_RRR(r0, r1, r2)  		=> insn!(0b0010_1011_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::ADR_RI(r0, i0)  				=> insn!(0b0001_0000_0000_0000_0000_0000_0000_0000, (0b0), r0, 0, ((((i0 >> 2) & 0x7FFFF) << 5) | ((i0 & 0b11) << 29)), 0, ret),
		TInsn::ADRP_RI(r0, i0)  			=> insn!(0b1001_0000_0000_0000_0000_0000_0000_0000, (0b0), r0, 0, ((((i0 >> 14) & 0x7FFFF) << 5) | (((i0 >> 12) & 0b11) << 29)), 0, ret),
		TInsn::AND_RRR(r0, r1, r2)  		=> insn!(0b0000_1010_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::ANDS_RRRF(r0, r1, r2, (sft, i0))
											=> insn!(0b0110_1010_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ((sft as u32) & 0b11), 22, ((i0 & 0x3F) as u32), 10, ret),
		TInsn::ANDS_RRI(r0, r1, i0)  		=> insn!(0b0111_0010_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, (i0 & 0xFFF), 10, ret),
		TInsn::B_I(i0)  					=> insn!(0b0001_0100_0000_0000_0000_0000_0000_0000, ((i0 >> 2) & 0x03FFFFFF), 0, ret),
		TInsn::BC_IC(i0, c0)  				=> insn!(0b0101_0100_0000_0000_0000_0000_0000_0000, ((i0 >> 2) & 0x0007FFFF), 5, c0, 0, ret),
		TInsn::BL_I(i0)  					=> insn!(0b1001_0100_0000_0000_0000_0000_0000_0000, ((i0 >> 2) & 0x03FFFFFF), 0, ret),
		TInsn::BLR_R(r0)  					=> insn!(0b1101_0110_0011_1111_0000_0000_0000_0000, (0b0), r0, 5, ret),
		TInsn::BR_R(r0)  					=> insn!(0b1101_0110_0001_1111_0000_0000_0000_0000, (0b0), r0, 5, ret),
		TInsn::CAS_RRM(r0, r1, (r2, _, _, _))
											=> insn!(0b1000_1000_1010_0000_0111_1100_0000_0000, (0b1 << 30), r0, 16, r1, 0, r2, 5, ret),
		TInsn::CBNZ_RI(r0, i0)  			=> insn!(0b0011_0101_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, ((i0 >> 2) & 0x7FFFF), 5, ret),
		TInsn::CBZ_RI(r0, i0)  				=> insn!(0b0011_0100_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, ((i0 >> 2) & 0x7FFFF), 5, ret),
		TInsn::CSEL_RRRC(r0, r1, r2, c0) 	=> insn!(0b0001_1010_1000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, (c0 as u32), 12, ret),
		TInsn::CSINC_RRRC(r0, r1, r2, c0) 	=> insn!(0b0001_1010_1000_0000_0000_0100_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, (c0 as u32), 12, ret),
		TInsn::CSINV_RRRC(r0, r1, r2, c0) 	=> insn!(0b0101_1010_1000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, (c0 as u32), 12, ret),
		TInsn::CSNEG_RRRC(r0, r1, r2, c0) 	=> insn!(0b0101_1010_1000_0000_0000_0100_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, (c0 as u32), 12, ret),
		TInsn::EOR_RRR(r0, r1, r2)  	 	=> insn!(0b0100_1010_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::LDP_RRM(r0, r1, (r2, r3, i0, m_acc)) => {
			let i0 = if let Reg::W(_) = r0 { i0 >> 2 } else { i0 >> 3 };
			match m_acc {
				MemAccCls::PstIndex  		=> insn!(0b0010_1000_1100_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 10, r2, 5, (i0 & 0x7F), 15, ret),
				MemAccCls::PreIndex  		=> insn!(0b0010_1001_1100_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 10, r2, 5, (i0 & 0x7F), 15, ret),
				MemAccCls::Offset  			=> insn!(0b0010_1001_0100_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 10, r2, 5, (i0 & 0x7F), 15, ret),
			}
		}
		TInsn::LDR_RM(r0, (r1, r2, i0, m_acc)) => {
			let i0 = if let Reg::W(_) = r0 { i0 >> 2 } else { i0 >> 3 };
			if r2 == Reg::INV {
				// LDR (immediate)
				match m_acc {
					MemAccCls::PstIndex  	=> insn!(0b1011_1000_0100_0000_0000_0100_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
					MemAccCls::PreIndex  	=> insn!(0b1011_1000_0100_0000_0000_1100_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
					MemAccCls::Offset  	 	=> insn!(0b1011_1001_0100_0000_0000_0000_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0xFFF), 10, ret),
				}
			} else {
				// LDR (register)
				match m_acc {
					MemAccCls::Offset  		=> insn!(0b1011_1000_0110_0000_0000_1000_0000_0000, (0b1 << 30), r0, 0, r1, 5, r2, 16, ret),
					_ => {
						pr_err!("Wrong memory access class for LDP (register)\n");
					}
				}
			}
		}
		TInsn::LDRB_RM(r0, (r1, r2, i0, m_acc)) => {
			match m_acc {
				MemAccCls::PstIndex  		=> insn!(0b0011_1000_0100_0000_0000_0100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::PreIndex  		=> insn!(0b0011_1000_0100_0000_0000_1100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::Offset  			=> insn!(0b0011_1001_0100_0000_0000_0000_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0xFFF), 10, ret),
			}
		}
		TInsn::LDRH_RM(r0, (r1, r2, i0, m_acc)) => {
			match m_acc {
				MemAccCls::PstIndex  		=> insn!(0b0111_1000_0100_0000_0000_0100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::PreIndex  		=> insn!(0b0111_1000_0100_0000_0000_1100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::Offset  			=> insn!(0b0111_1001_0100_0000_0000_0000_0000_0000, (0b0), r0, 0, r1, 5, ((i0 >> 1) & 0xFFF), 10, ret),
			}
		}

		TInsn::LDTRB_RM(r0, (r1, r2, i0, m_acc)) => {
			match m_acc {
				MemAccCls::Offset  			=> insn!(0b0011_1000_0100_0000_0000_1000_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				_ 							=> pr_err!("Wrong MemAccCls for LDTRB\n"),
			}
		}
		TInsn::LDTRH_RM(r0, (r1, r2, i0, m_acc)) => {
			match m_acc {
				MemAccCls::Offset  			=> insn!(0b0111_1000_0100_0000_0000_1000_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				_ 							=> pr_err!("Wrong MemAccCls for LDTRH\n"),
			}
		}

		TInsn::LDUR_RM(r0, (r1, r2, i0, m_acc)) 
											=> insn!(0b1011_1000_0100_0000_0000_0000_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
		TInsn::LSL_RRR(r0, r1, r2)  		=> insn!(0b0001_1010_1100_0000_0010_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::LSR_RRR(r0, r1, r2)  		=> insn!(0b0001_1010_1100_0000_0010_0100_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::MADD_RRRR(r0, r1, r2, r3)	 
											=> insn!(0b0001_1011_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, r3, 10, ret),
		
		TInsn::MOVK_RIF(r0, i0, sft)  		=> insn!(0b0111_0010_1000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, (i0 & 0xFFFF), 5, (((sft.1 >> 4) & 0b11) as u32), 21, ret),
		TInsn::MOVZ_RIF(r0, i0, sft)  		=> insn!(0b0101_0010_1000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, (i0 & 0xFFFF), 5, (((sft.1 >> 4) & 0b11) as u32), 21, ret),
		TInsn::MRS_RS(r0, s0)  				=> insn!(0b1101_0101_0011_0000_0000_0000_0000_0000, (0b0), r0, 0, (s0 as u32 & 0x7FFF), 5, ret),
		TInsn::MSR_SR(s0, r0)  				=> insn!(0b1101_0101_0001_0000_0000_0000_0000_0000, (0b0), r0, 0, (s0 as u32 & 0x7FFF), 5, ret),  // The operands are switched to match the macro

		TInsn::NOP  						=> insn!(0b1101_0101_0000_0011_0010_0000_0001_1111, ret),
		TInsn::ORR_RRR(r0, r1, r2)  		=> insn!(0b0010_1010_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::RET_R(r0)  					=> insn!(0b1101_0110_0101_1111_0000_0000_0000_0000, (0b0), r0, 5, ret),
		TInsn::ROR_RRR(r0, r1, r2)  		=> insn!(0b0001_1010_1100_0000_0010_1100_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::STP_RRM(r0, r1, (r2, r3, i0, m_acc)) => {
			let i0 = if let Reg::W(_) = r0 { i0 >> 2 } else { i0 >> 3 };
			match m_acc {
				MemAccCls::PstIndex  		=> insn!(0b0010_1000_1000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 10, r2, 5, (i0 & 0x7F), 15, ret),
				MemAccCls::PreIndex  		=> insn!(0b0010_1001_1000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 10, r2, 5, (i0 & 0x7F), 15, ret),
				MemAccCls::Offset  			=> insn!(0b0010_1001_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 10, r2, 5, (i0 & 0x7F), 15, ret),
			}
		}
		TInsn::STLXR_RRM(r0, r1, (r2, _, _, _))
											=> insn!(0b1000_1000_0000_0000_1111_1100_0000_0000, (0b1 << 30), r1, 0, r0, 16, r2, 5, ret),
		TInsn::STR_RM(r0, (r1, r2, i0, m_acc)) => {
			let i0 = if let Reg::W(_) = r0 { i0 >> 2 } else { i0 >> 3 };
			if r2 == Reg::INV {
				// STP (immediate)
				match m_acc {
					MemAccCls::PstIndex 	=> insn!(0b1011_1000_0000_0000_0000_0100_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
					MemAccCls::PreIndex 	=> insn!(0b1011_1000_0000_0000_0000_1100_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
					MemAccCls::Offset  		=> insn!(0b1011_1001_0000_0000_0000_0000_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0xFFF), 10, ret),
				}
			} else {
				// STP (register)
				match m_acc {
					MemAccCls::Offset  		=> insn!(0b1011_1000_0010_0000_0000_1000_0000_0000, (0b1 << 30), r0, 0, r1, 5, r2, 16, ret),
					_ => {
						pr_err!("Wrong memory access class for STP (register)\n");
					}
				}
			}
		}
		TInsn::STRB_RM(r0, (r1, r2, i0, m_acc)) => {
			match m_acc {
				MemAccCls::PstIndex  		=> insn!(0b0011_1000_0000_0000_0000_0100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::PreIndex  		=> insn!(0b0011_1000_0000_0000_0000_1100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::Offset  			=> insn!(0b0011_1001_0000_0000_0000_0000_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0xFFF), 10, ret),
			}
		}
		TInsn::STRH_RM(r0, m0) => {
			let (r1, r2, i0, m_acc) = m0;
			match m_acc {
				MemAccCls::PstIndex  		=> insn!(0b0111_1000_0000_0000_0000_0100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::PreIndex  		=> insn!(0b0111_1000_0000_0000_0000_1100_0000_0000, (0b0), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
				MemAccCls::Offset  			=> insn!(0b0111_1001_0000_0000_0000_0000_0000_0000, (0b0), r0, 0, r1, 5, ((i0 >> 1) & 0xFFF), 10, ret),
			}
		}
		TInsn::STUR_RM(r0, (r1, r2, i0, m_acc)) 
											=> insn!(0b1011_1000_0000_0000_0000_0000_0000_0000, (0b1 << 30), r0, 0, r1, 5, (i0 & 0x1FF), 12, ret),
		TInsn::STXR_RRR(r0, r1, r2) 		=> insn!(0b1000_1000_0000_0000_0111_1100_0000_0000, (0b1 << 30), r0, 16, r1, 0, r2, 5, ret),
		TInsn::SUB_RRI(r0, r1, i0) 			=> insn!(0b0101_0001_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, ((i0 as u32) & 0xFFF), 10, ret),
		TInsn::SUB_RRR(r0, r1, r2) 			=> insn!(0b0100_1011_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::SUBS_RRI(r0, r1, i0) 		=> insn!(0b0111_0001_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, ((i0 as u32) & 0xFFF), 10, ret),
		TInsn::SUBS_RRR(r0, r1, r2) 		=> insn!(0b0110_1011_0000_0000_0000_0000_0000_0000, (0b1 << 31), r0, 0, r1, 5, r2, 16, ret),
		TInsn::SVC_I(i0)  					=> insn!(0b1101_0100_0000_0000_0000_0000_0000_0001, (i0 & 0xFFFF), 5, ret),
		TInsn::TBNZ_RII(r0, i0, i1) 		=> insn!(0b0011_0111_0000_0000_0000_0000_0000_0000, (0b0), r0, 0, ((((i0 & 0b111111) >> 5) << 31) | ((i0 & 0b11111) << 19)), 0, ((i1 >> 2) & 0x3FFF), 5, ret),
		TInsn::TBZ_RII(r0, i0, i1) 			=> insn!(0b0011_0110_0000_0000_0000_0000_0000_0000, (0b0), r0, 0, ((((i0 & 0b111111) >> 5) << 31) | ((i0 & 0b11111) << 19)), 0, ((i1 >> 2) & 0x3FFF), 5, ret),
		
		// Alias
		TInsn::CMN_RR(r0, r1)  				=> { match r0 { Reg::W(_) => return asm_one(TInsn::ADDS_RRR(Reg::W(31), r0, r1)), _ => return asm_one(TInsn::ADDS_RRR(Reg::X(31), r0, r1)), } }
		TInsn::CMP_RI(r0, i0)  				=> { match r0 { Reg::W(_) => return asm_one(TInsn::SUBS_RRI(Reg::W(31), r0, i0)), _ => return asm_one(TInsn::SUBS_RRI(Reg::X(31), r0, i0)), } }
		TInsn::CMP_RR(r0, r1)  				=> { match r0 { Reg::W(_) => return asm_one(TInsn::SUBS_RRR(Reg::W(31), r0, r1)), _ => return asm_one(TInsn::SUBS_RRR(Reg::X(31), r0, r1)), } }
		TInsn::CINC_RRC(r0, r1, c0) 		=> { return asm_one(TInsn::CSINC_RRRC(r0, r1, r1, c0.inverse())); }
		TInsn::CNEG_RRC(r0, r1, c0) 		=> { return asm_one(TInsn::CSNEG_RRRC(r0, r1, r1, c0.inverse())); }
		TInsn::CSET_RC(r0, c0) 				=> { return asm_one(TInsn::CSINC_RRRC(r0, Reg::X(31), Reg::X(31), c0.inverse()))}
		TInsn::MOV_RI(r0, i0)  				=> { return asm_one(TInsn::MOVZ_RIF(r0, i0, (ShiftCls::LSL, 0))); }
		TInsn::MOV_RR(r0, r1)  				=> { 
													if r0 == Reg::SP || r1 == Reg::SP {
														return asm_one(TInsn::ADD_RRI(r0, r1, 0)); 
													} else { 
														return asm_one(TInsn::ORR_RRR(r0, Reg::X(31), r1)); 
													} 
												}
		TInsn::MUL_RRR(r0, r1, r2)  		=> { return asm_one(TInsn::MADD_RRRR(r0, r1, r2, Reg::X(31))); }
		TInsn::NEG_RR(r0, r1)  				=> { return asm_one(TInsn::SUB_RRR(r0, Reg::X(31), r1)); }
		TInsn::TST_RI(r0, i0) 				=> { match r0 { Reg::W(_) => return asm_one(TInsn::ANDS_RRI(Reg::W(31), r0, i0)), _ => return asm_one(TInsn::ANDS_RRI(Reg::X(31), r0, i0)), } }
	}
	
	ret
}

/// Macro `assem` takes in a list of `TInsn`s and outputs the assembled byte code in `Vec<u8>`.
/// 
/// # Example
/// 
/// ```rust
/// use assem::{*, TInsn::*};
/// 
/// fn main() {
///     let ret = assem![
///         ; ADD_RRI   (Reg::X(12), Reg::X(23), 0x3F6)
///         ; BC_IC     (0x3F8, Cond::NE)
///         ; BL_I      (0x3F8)
///         ; BLR_R     (Reg::X(23))
///         ; CMP_RR    (Reg::X(23), Reg::X(12))
///         ; MOV_RI    (Reg::X(23), 0x3F6)
///         ; NOP
///         ; ORR_RRR   (Reg::X(8), Reg::X(23), Reg::X(7))
///         ; ROR_RRR   (Reg::X(23), Reg::X(23), Reg::X(13))
///         ; SUB_RRI   (Reg::X(6), Reg::X(23), 0x3F6)
///         ; SVC
/// 		; RET
///     ];
///     println!("{:02x?}", ret);
/// }
/// ```
#[macro_export]
macro_rules! assem {
	($(;$x:expr)*) => {{
		let mut insns = Vec::new();
		$(insns.push($x, GFP_ATOMIC).unwrap();)*
		asm(&insns)
	}};
}

/// Checks the `MemAccCls` of the instruction, now supports LDP/STP/LDR/LDRB/LDRH/STR/STRB/STRH
pub(crate) fn check_mem_acc_cls(insn_bytes: &[u8], insn_type: Insn) -> MemAccCls {
	if insn_bytes.len() != 4 {
		pr_err!("Incorrect insn_bytes for check_mem_acc_cls, defaulting to Offset\n");
		return MemAccCls::Offset;
	}

	// Safety: `insn_bytes` is guaranteed to be 4 bytes long
	// ans bytes are already in small-endian order, we don't need to reverse it.
	let bits = unsafe { *(insn_bytes.as_ptr() as *const u32) };

	match insn_type {
		Insn::ARM64_INS_LDP |
		Insn::ARM64_INS_STP => {
			if bits & (0b1 << 23) != 0 {
				// If 23rd bit is 1, Pre or Post
				if bits & (0b1 << 24) != 0 {
					return MemAccCls::PreIndex;
				} else {
					return MemAccCls::PstIndex;
				}
			} else if bits & (0b1 << 24) != 0 {
				// If 23rd bit is 0 and 24th bit is 1, Offset
				return MemAccCls::Offset;
			} else {
				pr_err!("Impossible MemAccCls, defaulting to Offset\n");
				return MemAccCls::Offset;
			}
		}
		Insn::ARM64_INS_LDR  |
		Insn::ARM64_INS_LDRB |
		Insn::ARM64_INS_LDRH |
		Insn::ARM64_INS_STR  |
		Insn::ARM64_INS_STRB |
		Insn::ARM64_INS_STRH => {
			if bits & (0b1 << 24) == 0 && bits & (0b1 << 10) != 0 {
				// If 24th bit is 0 and 10th bit is 1, Pre or Post
				if bits & (0b1 << 11) != 0 {
					return MemAccCls::PreIndex;
				} else {
					return MemAccCls::PstIndex;
				}
			} else if bits & (0b1 << 24) != 0 {
				// Offset if 24th bit is 1
				return MemAccCls::Offset;
			} else {
				pr_err!("Impossible MemAccCls, defaulting to Offset\n");
				return MemAccCls::Offset;
			}
		}
		_ => {
			pr_err!("Incorrect parameter for check_mem_acc_cls, defaulting to Offset\n");
			return MemAccCls::Offset;
		}
	}
}