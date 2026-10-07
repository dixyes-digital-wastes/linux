// SPDX-License-Identifier: GPL-2.0-only
/*
 * Emulation of the LSE atomic instructions (FEAT_LSE)
 *
 * A CPU without FEAT_LSE takes an undefined instruction exception on the
 * atomic memory operations, the swaps and the compare and swaps, which a
 * binary built for a newer target can contain. Such an operation is carried
 * out here instead, with the permissions of the task that faulted, and the
 * exception is not passed on
 *
 * Only EL0 is handled: the kernel's own atomics are chosen at boot between
 * these instructions and the exclusive sequences, and neither reaches this
 * path
 */

#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/hash.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include <asm/insn-def.h>
#include <asm/ptrace.h>
#include <asm/traps.h>

#include "lse_block_code.h"

/*
 *   size 111000 A R 1 Rs opc 00 Rn Rt
 *
 * The size is the two top bits, 0 to 3 for byte, halfword, word and doubleword,
 * and opc numbers the operation, 0 to 7 for the memory operations and 8 for
 * the swap. LDAPR shares this class, and takes a number above them
 */
#define LSE_AMO_MASK		0x3f200c00
#define LSE_AMO_VALUE		0x38200000
#define LSE_AMO_OPC(insn)	(((insn) >> 12) & 0xf)
#define LSE_OPC_SWP		8

/*
 *   size 001000 1 A 1 Rs L 11111 Rn Rt
 *
 * The comparand is in Rs, which the old value is written back to whether the
 * store happens or not, and what is stored is in Rt
 */
#define LSE_CAS_MASK		0x3fa07c00
#define LSE_CAS_VALUE		0x08a07c00

#define LSE_SIZE(insn)		((insn) >> 30)
#define LSE_RS(insn)		(((insn) >> 16) & 0x1f)
#define LSE_RN(insn)		(((insn) >> 5) & 0x1f)
#define LSE_RT(insn)		((insn) & 0x1f)

/* the operations in the order the encoding numbers them */
enum lse_op {
	LSE_ADD, LSE_CLR, LSE_EOR, LSE_SET,
	LSE_SMAX, LSE_SMIN, LSE_UMAX, LSE_UMIN,
	LSE_SWP, LSE_CAS,
};

struct lse_insn {
	enum lse_op	op;
	u8		size;
	u8		rs;
	u8		rt;
	u8		rn;
};

/*
 * Whether a site that keeps trapping is sent to a block that makes the
 * operation without an exception, and after how many traps: lse_rewrite=2 on
 * the command line, or a write to <debugfs>/lse_emul/rewrite. Zero is a block
 * at the first trap, and a count below zero is no block at all
 */
static int lse_rewrite = 2;
core_param(lse_rewrite, lse_rewrite, int, 0644);

/* The bytes a block saves its two registers in */
#define LSE_FRAME_BYTES		(2 * sizeof(u64))

/* The sites that have trapped, as far as they are worth counting */
#define LSE_HOT_SLOTS		256

struct lse_hot {
	unsigned long	site;
	unsigned int	traps;
};

static DEFINE_PER_CPU(struct lse_hot[LSE_HOT_SLOTS], lse_hot);

static void lse_block_try(struct pt_regs *regs, const struct lse_insn *lse,
			  u32 insn);

static atomic_long_t lse_emul_traps;
static atomic_long_t lse_emul_blocks;
static atomic_long_t lse_emul_stale;
static atomic_long_t lse_sp_zero;
static atomic_long_t lse_sp_misaligned;
static atomic_long_t lse_sp_unwritable;

static bool lse_decode(u32 insn, struct lse_insn *lse)
{
	u32 opc;

	if ((insn & LSE_CAS_MASK) == LSE_CAS_VALUE) {
		lse->op = LSE_CAS;
	} else if ((insn & LSE_AMO_MASK) == LSE_AMO_VALUE) {
		opc = LSE_AMO_OPC(insn);
		if (opc > LSE_OPC_SWP)
			return false;
		lse->op = opc;
	} else {
		return false;
	}

	lse->size = LSE_SIZE(insn);
	lse->rs = LSE_RS(insn);
	lse->rt = LSE_RT(insn);
	lse->rn = LSE_RN(insn);

	return true;
}

/* The width of the access, which is what the size field counts in bits */
static unsigned int lse_access_size(u8 size)
{
	return 1 << size;
}

/*
 * A compare and swap of one width, made of the exclusive pair the
 * architecture has: the address is read exclusively, the comparand is
 * compared with what was read, and the value is stored exclusively where they
 * match. An exclusive store fails when another CPU has written the address
 * since the load, and the whole sequence is then taken again, which is how the
 * atomics in atomic_ll_sc.h make progress
 *
 * The value read is left in *old, which is the comparand where the store
 * happened and the value now there where it did not. Only the exclusive pair
 * touches the address, so the operation is atomic with every other exclusive
 * access to it
 */
#define LSE_CMPXCHG(name, ldxr, stxr, mod, q)				       \
static int lse_cmpxchg_##name(q __user *addr, u64 comparand, u64 value,	       \
			      u64 *old)					       \
{									       \
	int ret = 0;							       \
	u64 val, tmp;							       \
									       \
	uaccess_enable_privileged();					       \
	asm volatile(							       \
	"	prfm	pstl1strm, %[addr]\n"				       \
	"1:	" ldxr "	%" #mod "[val], %[addr]\n"		       \
	"	eor	%" #mod "[tmp], %" #mod "[val], %" #mod "[cmp]\n"      \
	"	cbnz	%" #mod "[tmp], 3f\n"				       \
	"2:	" stxr "	%w[tmp], %" #mod "[value], %[addr]\n"	       \
	"	cbnz	%w[tmp], 1b\n"					       \
	"3:	dmb	ish\n"						       \
	_ASM_EXTABLE_UACCESS_ERR(1b, 3b, %w0)				       \
	_ASM_EXTABLE_UACCESS_ERR(2b, 3b, %w0)				       \
	: [ret] "+r" (ret), [val] "=&r" (val), [tmp] "=&r" (tmp),	       \
	  [addr] "+Q" (*addr)						       \
	: [cmp] "r" (comparand), [value] "r" (value)			       \
	: "memory");							       \
	uaccess_disable_privileged();					       \
									       \
	if (!ret)							       \
		*old = val;						       \
									       \
	return ret;							       \
}

LSE_CMPXCHG(byte, "ldxrb", "stxrb", w, u8)
LSE_CMPXCHG(half, "ldxrh", "stxrh", w, u16)
LSE_CMPXCHG(word, "ldxr", "stxr", w, u32)
LSE_CMPXCHG(xword, "ldxr", "stxr", x, u64)

/* The value in the mapping, read the way the task that faulted would read it */
static int lse_load(u8 size, unsigned long addr, u64 *value)
{
	/* the narrower forms zero extend */
	*value = 0;

	switch (size) {
	case 0:
		return get_user(*(u8 *)value, (u8 __user *)addr);
	case 1:
		return get_user(*(u16 *)value, (u16 __user *)addr);
	case 2:
		return get_user(*(u32 *)value, (u32 __user *)addr);
	default:
		return get_user(*(u64 *)value, (u64 __user *)addr);
	}
}

/*
 * The same, storing the value where the comparand is what is there, and
 * leaving what was there in *old. Returns whether the access could be made
 */
static int lse_store(u8 size, unsigned long addr, u64 comparand, u64 value,
		     u64 *old)
{
	u64 prev = 0;
	int ret;

	switch (size) {
	case 0:
		ret = lse_cmpxchg_byte((u8 __user *)addr, comparand, value,
				       &prev);
		break;
	case 1:
		ret = lse_cmpxchg_half((u16 __user *)addr, comparand, value,
				       &prev);
		break;
	case 2:
		ret = lse_cmpxchg_word((u32 __user *)addr, comparand, value,
				       &prev);
		break;
	default:
		ret = lse_cmpxchg_xword((u64 __user *)addr, comparand, value,
					&prev);
		break;
	}

	*old = prev;

	return ret;
}

/* The operand of a narrow operation is the low part of the register */
static u64 lse_operand(u64 value, u8 size)
{
	switch (size) {
	case 0:
		return value & 0xff;
	case 1:
		return value & 0xffff;
	case 2:
		return value & 0xffffffff;
	default:
		return value;
	}
}

/* The same, widened to the sign it carries for the signed minima and maxima */
static s64 lse_signed(u64 value, u8 size)
{
	switch (size) {
	case 0:
		return (s8)value;
	case 1:
		return (s16)value;
	case 2:
		return (s32)value;
	default:
		return value;
	}
}

static u64 lse_apply(enum lse_op op, u8 size, u64 old, u64 operand)
{
	switch (op) {
	case LSE_ADD:
		return old + operand;
	case LSE_CLR:
		return old & ~operand;
	case LSE_EOR:
		return old ^ operand;
	case LSE_SET:
		return old | operand;
	case LSE_SMAX:
		return lse_signed(old, size) > lse_signed(operand, size) ?
			old : operand;
	case LSE_SMIN:
		return lse_signed(old, size) < lse_signed(operand, size) ?
			old : operand;
	case LSE_UMAX:
		return old > operand ? old : operand;
	case LSE_UMIN:
		return old < operand ? old : operand;
	case LSE_SWP:
	case LSE_CAS:
		break;
	}

	/* the swap stores the operand; the compare and swap is made elsewhere */
	return operand;
}

/* The compare and swap, which writes the old value back to its comparand */
static bool lse_cas(struct pt_regs *regs, const struct lse_insn *lse,
		    unsigned long addr, u32 insn)
{
	u64 comparand, value, old;

	/* Rs=31 and Rt=31 are the zero register */
	comparand = lse->rs == 31 ? 0 : regs->regs[lse->rs];
	value = lse->rt == 31 ? 0 : regs->regs[lse->rt];
	comparand = lse_operand(comparand, lse->size);

	if (lse_store(lse->size, addr, comparand, value, &old)) {
		undef_fault(addr, VM_READ | VM_WRITE);
		return true;
	}

	if (lse->rs != 31)
		regs->regs[lse->rs] = old;

	lse_block_try(regs, lse, insn);
	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);

	return true;
}

/*
 * Whether the task is allowed to write to the address, which the exclusive
 * pair cannot be asked: a store from the kernel is allowed where the mapping
 * is read only for the task, so what the task may write is asked here
 *
 * An address in no mapping at all is left to the exclusive access, which
 * either faults or lets the fault handler grow the stack over it. What a
 * mapping allows can change before the access is made, where the hardware
 * would have taken the check and the access as one
 */
static bool lse_writable(unsigned long addr)
{
	struct vm_area_struct *vma;
	bool writable = true;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, untagged_addr(addr));
	if (vma && !(vma->vm_flags & VM_WRITE))
		writable = false;
	mmap_read_unlock(current->mm);

	return writable;
}

enum lse_stack {
	LSE_STACK_OK,
	LSE_STACK_ZERO,
	LSE_STACK_MISALIGNED,
	LSE_STACK_UNWRITABLE,
};

/*
 * What the stack pointer of the task says about the stack being usable where
 * it was stopped: it may be zero, unaligned where the architecture requires it
 * to be aligned, or point into no mapping a frame can be pushed on
 */
static enum lse_stack lse_stack_state(struct pt_regs *regs)
{
	struct vm_area_struct *vma;
	enum lse_stack state;

	if (!regs->sp)
		return LSE_STACK_ZERO;

	if (regs->sp & 15)
		return LSE_STACK_MISALIGNED;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, regs->sp - 1);
	state = vma && (vma->vm_flags & (VM_WRITE | VM_GROWSDOWN)) ?
		LSE_STACK_OK : LSE_STACK_UNWRITABLE;
	mmap_read_unlock(current->mm);

	return state;
}

/* What the stack looked like where the task was stopped, for the count of it */
static void lse_note_stack(struct pt_regs *regs)
{
	switch (lse_stack_state(regs)) {
	case LSE_STACK_ZERO:
		atomic_long_inc(&lse_sp_zero);
		break;
	case LSE_STACK_MISALIGNED:
		atomic_long_inc(&lse_sp_misaligned);
		break;
	case LSE_STACK_UNWRITABLE:
		atomic_long_inc(&lse_sp_unwritable);
		break;
	default:
		break;
	}
}

/*
 * Whether the site has trapped often enough to be worth a block, which is
 * counted where it is cheap: a slot of the running processor's own table, with
 * a site that has not been seen before taking the slot over. A count that
 * belongs to another task's site only makes a block come sooner
 */
static bool lse_hot_site(unsigned long site)
{
	struct lse_hot *hot, *slot;
	bool ready;

	preempt_disable();
	hot = this_cpu_ptr(lse_hot);
	slot = &hot[hash_long(site, ilog2(LSE_HOT_SLOTS))];
	if (slot->site != site) {
		slot->site = site;
		slot->traps = 0;
	}
	slot->traps++;
	ready = slot->traps >= (unsigned int)lse_rewrite;
	preempt_enable();

	return ready;
}

/* The two registers a block works in, which the instruction itself does not */
static void lse_scratch(const struct lse_insn *lse, u8 *first, u8 *second)
{
	u8 picked[2];
	unsigned int n = 0;

	for (u8 r = 0; r < 31 && n < ARRAY_SIZE(picked); r++) {
		if (r == lse->rs || r == lse->rt || r == lse->rn)
			continue;
		picked[n++] = r;
	}

	*first = picked[0];
	*second = picked[1];
}

/*
 * The site has trapped enough to be worth a block, which is put in place where
 * one can be made for it. The operation is carried out here either way, so
 * nothing depends on whether one was
 */
static void lse_block_try(struct pt_regs *regs, const struct lse_insn *lse,
			  u32 insn)
{
	unsigned long site = instruction_pointer(regs);
	u32 code[LSE_BLOCK_CODE_MAX];
	u8 first, second;
	unsigned int count;

	if (lse_rewrite < 0 || !lse_hot_site(site))
		return;
	if (lse_stack_state(regs) != LSE_STACK_OK)
		return;

	lse_scratch(lse, &first, &second);
	count = lse_block_code(lse->op, lse->size, lse->rs, lse->rt, lse->rn,
			       first, second, site, code);
	if (!count)
		return;

	if (lse_block_install(regs, insn, site, BIT(first) | BIT(second),
			      LSE_FRAME_BYTES, code, count))
		atomic_long_inc(&lse_emul_blocks);
}

/*
 * Performs the instruction an EL0 task was stopped on
 *
 * Returns false when it is not one of the LSE atomics: nothing has changed,
 * and the caller answers for the exception as it would have without this
 */
bool try_emulate_lse(struct pt_regs *regs, u32 insn)
{
	struct lse_insn lse;
	unsigned long addr;
	u64 operand, value;

	/* AArch32 has no LSE atomics */
	if (compat_user_mode(regs))
		return false;

	if (!lse_decode(insn, &lse)) {
		/*
		 * The branch a block rewrite puts at a site, which cannot trap:
		 * this processor ran the operation that was there before, and
		 * what it ran is not what the site holds now
		 */
		if ((insn & LSE_B_MASK) == LSE_B) {
			atomic_long_inc(&lse_emul_traps);
			atomic_long_inc(&lse_emul_stale);
			undef_run_again(regs);

			return true;
		}

		return false;
	}

	atomic_long_inc(&lse_emul_traps);

	/* Rn=31 is the stack pointer, not the zero register */
	addr = lse.rn == 31 ? regs->sp : regs->regs[lse.rn];

	/*
	 * An atomic access is only allowed to be unaligned where ARMv8.4-LSE
	 * is implemented, and takes the Alignment fault before anything else
	 */
	if (!undef_unaligned_ok && !undef_aligned(insn, addr)) {
		force_signal_inject(SIGBUS, BUS_ADRALN, addr, 0);
		return true;
	}

	lse_note_stack(regs);

	/*
	 * The exclusive pair has no unprivileged form, so what the task may
	 * reach and what it may write are checked here, rather than done with
	 * privileges it does not have
	 */
	if (!access_ok((void __user *)addr, lse_access_size(lse.size)) ||
	    !lse_writable(addr)) {
		undef_fault(addr, VM_READ | VM_WRITE);
		return true;
	}
	addr = (unsigned long)__uaccess_mask_ptr((void __user *)addr);

	if (lse.op == LSE_CAS)
		return lse_cas(regs, &lse, addr, insn);

	/* Rs=31 is the zero register */
	operand = lse.rs == 31 ? 0 : regs->regs[lse.rs];
	operand = lse_operand(operand, lse.size);

	for (;;) {
		u64 prev, new;

		if (lse_load(lse.size, addr, &prev)) {
			undef_fault(addr, VM_READ | VM_WRITE);
			return true;
		}

		new = lse_apply(lse.op, lse.size, prev, operand);

		if (lse_store(lse.size, addr, prev, new, &value)) {
			undef_fault(addr, VM_READ | VM_WRITE);
			return true;
		}

		/* the store happened where the value was still the one read */
		if (value == prev)
			break;
	}

	/* Rt=31 discards the value, and regs->regs[31] is not a register */
	if (lse.rt != 31)
		regs->regs[lse.rt] = value;

	lse_block_try(regs, &lse, insn);
	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);

	return true;
}

static int lse_emul_stats_show(struct seq_file *m, void *unused)
{
	seq_printf(m, "traps %lu\n", atomic_long_read(&lse_emul_traps));
	seq_printf(m, "sp_zero %lu\n", atomic_long_read(&lse_sp_zero));
	seq_printf(m, "sp_misaligned %lu\n",
		   atomic_long_read(&lse_sp_misaligned));
	seq_printf(m, "sp_unwritable %lu\n",
		   atomic_long_read(&lse_sp_unwritable));
	seq_printf(m, "blocks %lu\n", atomic_long_read(&lse_emul_blocks));
	seq_printf(m, "stale %lu\n", atomic_long_read(&lse_emul_stale));
	seq_printf(m, "block_faults %lu\n", lse_block_fault_count());

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(lse_emul_stats);

static int lse_emul_rewrite_get(void *data, u64 *val)
{
	*val = lse_rewrite;

	return 0;
}

static int lse_emul_rewrite_set(void *data, u64 val)
{
	lse_rewrite = val;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(lse_emul_rewrite_fops, lse_emul_rewrite_get,
			 lse_emul_rewrite_set, "%llu\n");

static int __init lse_emul_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("lse_emul", NULL);
	debugfs_create_file("stats", 0444, dir, NULL, &lse_emul_stats_fops);
	debugfs_create_file("rewrite", 0644, dir, NULL, &lse_emul_rewrite_fops);

	return 0;
}
late_initcall(lse_emul_init);
