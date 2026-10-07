/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The instructions a block that stands in for an LSE atomic site is made of
 *
 * The operation is made with the exclusive pair and the block branches back to
 * the instruction after the site. Two registers are lent to it, saved on the
 * stack in one store, which is why the first instruction of a block is that
 * store and nothing has happened if it faults
 *
 * Plain arithmetic on the words, so that the same code can be run over the
 * instructions it makes and read back by the disassembler
 */

#ifndef __LSE_BLOCK_CODE_H
#define __LSE_BLOCK_CODE_H

/*
 * The base of every instruction, with the register fields it carries left at
 * zero: what is written after each one is what the assembler makes of it
 */
#define LSE_STP_PRE	0xa9bf03e0	/* stp x0, x0, [sp, #-16]! */
#define LSE_LDP_POST	0xa8c103e0	/* ldp x0, x0, [sp], #16 */
#define LSE_B		0x14000000	/* b 0 */
#define LSE_CBNZ_W	0x35000000	/* cbnz w0, 0 */
#define LSE_CBNZ_X	0xb5000000	/* cbnz x0, 0 */
#define LSE_DMB_ISH	0xd5033bbf	/* dmb ish */
#define LSE_LDXRB	0x085f7c00	/* ldxrb w0, [x0] */
#define LSE_LDXRH	0x485f7c00	/* ldxrh w0, [x0] */
#define LSE_LDXRW	0x885f7c00	/* ldxr w0, [x0] */
#define LSE_LDXR	0xc85f7c00	/* ldxr x0, [x0] */
#define LSE_STXRB	0x0800fc00	/* stlxrb w0, w0, [x0] */
#define LSE_STXRH	0x4800fc00	/* stlxrh w0, w0, [x0] */
#define LSE_STXRW	0x8800fc00	/* stlxr w0, w0, [x0] */
#define LSE_STXR	0xc800fc00	/* stlxr w0, x0, [x0] */
#define LSE_ADD_W	0x0b000000	/* add w0, w0, w0 */
#define LSE_ADD_X	0x8b000000	/* add x0, x0, x0 */
#define LSE_BIC_W	0x0a200000	/* bic w0, w0, w0 */
#define LSE_BIC_X	0x8a200000	/* bic x0, x0, x0 */
#define LSE_EOR_W	0x4a000000	/* eor w0, w0, w0 */
#define LSE_EOR_X	0xca000000	/* eor x0, x0, x0 */
#define LSE_ORR_W	0x2a000000	/* orr w0, w0, w0 */
#define LSE_ORR_X	0xaa000000	/* orr x0, x0, x0 */
#define LSE_MOV_W	0x2a0003e0	/* mov w0, w0 */
#define LSE_MOV_X	0xaa0003e0	/* mov x0, x0 */
#define LSE_AND_BYTE	0x12001c00	/* and w0, w0, #0xff */
#define LSE_AND_HALF	0x12003c00	/* and w0, w0, #0xffff */

/* Where each kind of field sits in the instructions above */
#define LSE_RT_SHIFT	0
#define LSE_RN_SHIFT	5
#define LSE_RA_SHIFT	10
#define LSE_RM_SHIFT	16

/* The instructions a block holds at most, and where they start in its slot */
#define LSE_BLOCK_CODE_MAX	16
#define LSE_BLOCK_CODE		32

/* The operation numbers of the encoding, which the generator is given */
#define LSE_OP_ADD	0
#define LSE_OP_CLR	1
#define LSE_OP_EOR	2
#define LSE_OP_SET	3
#define LSE_OP_SWP	8
#define LSE_OP_CAS	9

static inline u32 lse_rt(u32 insn, u32 rt)
{
	return insn | (rt << LSE_RT_SHIFT);
}

static inline u32 lse_rn(u32 insn, u32 rn)
{
	return insn | (rn << LSE_RN_SHIFT);
}

static inline u32 lse_rm(u32 insn, u32 rm)
{
	return insn | (rm << LSE_RM_SHIFT);
}

static inline u32 lse_ra(u32 insn, u32 ra)
{
	return insn | (ra << LSE_RA_SHIFT);
}

/* The two registers of a load or a store of a pair */
static inline u32 lse_pair(u32 insn, u32 first, u32 second)
{
	return lse_rt(lse_ra(insn, second), first);
}

/* The offset of a branch, counted in instructions from the branch itself */
static inline u32 lse_offset(u32 insn, long instructions)
{
	return insn | ((u32)instructions & 0x3ffffff);
}

/* The same for the conditional branch, which counts in bits [23:5] */
static inline u32 lse_cbnz(u32 insn, long instructions)
{
	return insn | (((u32)instructions & 0x7ffff) << 5);
}

/* The load or store of the exclusive pair, and the operation of one width */
static inline u32 lse_ldx(u32 size, u32 rt, u32 rn)
{
	u32 base = size == 0 ? LSE_LDXRB : size == 1 ? LSE_LDXRH :
		   size == 2 ? LSE_LDXRW : LSE_LDXR;

	return lse_rn(lse_rt(base, rt), rn);
}

static inline u32 lse_stx(u32 size, u32 rs, u32 rt, u32 rn)
{
	u32 base = size == 0 ? LSE_STXRB : size == 1 ? LSE_STXRH :
		   size == 2 ? LSE_STXRW : LSE_STXR;

	return lse_rn(lse_rm(lse_rt(base, rt), rs), rn);
}

static inline u32 lse_alu(u32 op, u32 size, u32 rd, u32 rn, u32 rm)
{
	u32 base;

	switch (op) {
	case LSE_OP_ADD:
		base = size == 3 ? LSE_ADD_X : LSE_ADD_W;
		break;
	case LSE_OP_CLR:
		base = size == 3 ? LSE_BIC_X : LSE_BIC_W;
		break;
	case LSE_OP_EOR:
		base = size == 3 ? LSE_EOR_X : LSE_EOR_W;
		break;
	default:
		base = size == 3 ? LSE_ORR_X : LSE_ORR_W;
		break;
	}

	return lse_rm(lse_rn(lse_rt(base, rd), rn), rm);
}

static inline u32 lse_mov(u32 size, u32 rd, u32 rm)
{
	return lse_rm(lse_rt(size == 3 ? LSE_MOV_X : LSE_MOV_W, rd), rm);
}

/*
 * The branch back to the instruction after the site, which only has an offset
 * once the block it ends has been placed
 */
static inline u32 lse_back(unsigned long site, unsigned long block,
			   unsigned int count)
{
	long at = (long)block + LSE_BLOCK_CODE + (long)(count - 1) * 4;

	return lse_offset(LSE_B, ((long)site + 4 - at) / 4);
}

/*
 * The instructions that make the operation of one site, with the two registers
 * the block works in given to it: the lower of the two is stored first, which
 * is the order the frame is read back in
 *
 * Returns how many instructions were written, or zero where the instruction is
 * not one a block can be made for: the operations that need a comparison are
 * left to the emulation, which may carry the flags over, and a site whose
 * destination is its address has nowhere to keep the old value
 */
static inline unsigned int lse_block_code(u32 op, u32 size, u32 rs, u32 rt,
					  u32 rn, u32 first, u32 second,
					  unsigned long site, u32 *code)
{
	unsigned int n = 0, loop;

	if (op != LSE_OP_SWP && op != LSE_OP_CAS && op > LSE_OP_SET)
		return 0;
	if (rn == 31 || first >= second || second > 30)
		return 0;
	if (first == rn || second == rn)
		return 0;
	if (op == LSE_OP_CAS && (first == rs || second == rs))
		return 0;
	if (op != LSE_OP_CAS && op != LSE_OP_SWP &&
	    (first == rs || second == rs))
		return 0;
	/*
	 * The old value is loaded into the destination before the operation is
	 * made, so a destination the loop still needs is a site no block can be
	 * made for: the address of a swap, and the operand of anything but the
	 * compare and swap
	 */
	if (op != LSE_OP_CAS && rt != 31 && (rt == rn || rt == rs))
		return 0;

	code[n++] = lse_pair(LSE_STP_PRE, first, second);
	loop = n;

	if (op == LSE_OP_CAS) {
		unsigned int mismatch, done;
		u32 differs = (size == 3 ? LSE_CBNZ_X : LSE_CBNZ_W) | second;

		/*
		 * The value that is there against the comparand: what differs
		 * is thrown away, and only the width of the access counts
		 */
		code[n++] = lse_ldx(size, first, rn);
		code[n++] = lse_alu(LSE_OP_EOR, size, second, first, rs);
		if (size == 0)
			code[n++] = lse_rn(lse_rt(LSE_AND_BYTE, second), second);
		else if (size == 1)
			code[n++] = lse_rn(lse_rt(LSE_AND_HALF, second), second);
		mismatch = n++;
		code[mismatch] = lse_cbnz(differs, 0);
		code[n] = lse_stx(size, second, rt, rn);
		n++;
		code[n] = lse_cbnz(LSE_CBNZ_W | second, (long)loop - (long)n);
		n++;
		done = n++;			/* the branch past the write back */
		code[done] = lse_offset(LSE_B, 2);
		code[mismatch] = lse_cbnz(differs, (long)n - (long)mismatch);
		code[n++] = lse_mov(size, rs, first);
	} else {
		/*
		 * The old value is what the destination takes, and where the
		 * instruction has no destination the register that stores the
		 * new one takes it instead
		 */
		code[n++] = lse_ldx(size, rt == 31 ? first : rt, rn);
		if (op == LSE_OP_SWP) {
			code[n] = lse_stx(size, second, rs, rn);
			n++;
		} else {
			code[n++] = lse_alu(op, size, first,
					    rt == 31 ? first : rt, rs);
			code[n] = lse_stx(size, second, first, rn);
			n++;
		}
		code[n] = lse_cbnz(LSE_CBNZ_W | second, (long)loop - (long)n);
		n++;
	}

	code[n++] = LSE_DMB_ISH;
	code[n++] = lse_pair(LSE_LDP_POST, first, second);
	code[n++] = lse_offset(LSE_B, 0);	/* back to the site, placed later */

	return n;
}

#endif /* __LSE_BLOCK_CODE_H */
