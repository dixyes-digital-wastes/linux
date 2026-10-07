// SPDX-License-Identifier: GPL-2.0-only
/*
 * Emulation of the RCpc acquire loads (FEAT_LRCPC)
 *
 * A CPU without FEAT_LRCPC takes an undefined instruction exception on the
 * LDAPR and LDAPUR families, which a binary built for a newer target can
 * contain. Such a load is made here instead, with the permissions of the task
 * that faulted, and the exception is not passed on
 *
 * Only EL0 is handled: the kernel's own RCpc loads are substituted at boot by
 * the alternatives in rwonce.h
 */

#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/insn-def.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>
#include <asm/traps.h>

/*
 *   size 111000 101111 111100 00 Rn Rt
 *
 * The size is the two top bits, 0 to 3 for byte, halfword, word and doubleword
 */
#define RCPC_LDAPR_MASK		0x3ffffc00
#define RCPC_LDAPR_VALUE	0x38bfc000

/*
 *   size 001101 01 imm9 00 Rn Rt
 *
 * The same four widths, with an unscaled offset in bits [20:12]
 */
#define RCPC_LDAPUR_MASK	0x3fe00c00
#define RCPC_LDAPUR_VALUE	0x19400000

/*   size 001000 110111 111111 00 Rn Rt */
#define RCPC_LDAR_VALUE		0x08dffc00

#define RCPC_SIZE_MASK		0xc0000000
#define RCPC_REG_MASK		0x3ff

#define RCPC_SIZE(insn)		((insn) >> 30)
#define RCPC_RN(insn)		(((insn) >> 5) & 0x1f)
#define RCPC_RT(insn)		((insn) & 0x1f)

/*
 * Whether to replace each load with the acquire load that does the same job
 * once it has trapped, which is off until it is asked for: rcpc_rewrite=1 on
 * the command line, or a write to <debugfs>/rcpc_emul/rewrite
 */
static bool rcpc_rewrite_enabled;
core_param(rcpc_rewrite, rcpc_rewrite_enabled, bool, 0644);

/*
 * Whether an unaligned load of this family is allowed here, which is what
 * ID_AA64MMFR2_EL1.AT reports: a Load-Acquire is only allowed to be unaligned
 * where ARMv8.4-LSE, and without it the load takes an Alignment fault before
 * any of its other behaviour is reached
 */
static bool rcpc_unaligned_ok __ro_after_init;

static atomic_long_t rcpc_emul_traps;
static atomic_long_t rcpc_emul_rewrites;

/* The unscaled form's imm9, bits [20:12], sign extended */
static s64 rcpc_imm9(u32 insn)
{
	return (s64)(s32)(insn << 11) >> 23;
}

/* Rn=31 is the stack pointer, not the zero register */
static unsigned long rcpc_base(struct pt_regs *regs, u32 insn)
{
	u32 rn = RCPC_RN(insn);

	return rn == 31 ? regs->sp : regs->regs[rn];
}

/*
 * Whether the address is aligned for the width of the access
 *
 * An acquire load is single copy atomic, and that is what requires natural
 * alignment, where the RCpc load it would stand in for may be read at any
 * alignment, so an unaligned one is left to the emulation
 */
static bool rcpc_aligned(u32 insn, unsigned long addr)
{
	switch (RCPC_SIZE(insn)) {
	case 0:
		return true;
	case 1:
		return !(addr & 1);
	case 2:
		return !(addr & 3);
	default:
		return !(addr & 7);
	}
}

/*
 * Replaces the load the task was stopped on with the acquire load that does
 * the same job, so that the next time it runs there is nothing to trap on
 *
 * What is written is the task's own copy of the page: a private mapping is
 * given one first, and a shared mapping is left alone, because the change
 * would be seen by every process that maps it. Whether this succeeds or not,
 * the load is carried out below, so nothing depends on it but speed
 */
static bool rcpc_rewrite(struct pt_regs *regs, u32 insn)
{
	unsigned long pc = instruction_pointer(regs);
	unsigned int gup_flags = FOLL_WRITE | FOLL_FORCE | FOLL_SPLIT_PMD;
	struct vm_area_struct *vma;
	struct folio *folio;
	struct page *page = NULL;
	u32 replacement;
	void *kaddr;
	int locked;
	long ret;

	if (!rcpc_rewrite_enabled)
		return false;

	/* the acquire load has no unscaled offset to carry over */
	if ((insn & RCPC_LDAPR_MASK) != RCPC_LDAPR_VALUE) {
		if ((insn & RCPC_LDAPUR_MASK) != RCPC_LDAPUR_VALUE)
			return false;
		if (rcpc_imm9(insn) != 0)
			return false;
	}

	replacement = RCPC_LDAR_VALUE | (insn & (RCPC_SIZE_MASK | RCPC_REG_MASK));

	mmap_read_lock(current->mm);
	for (;;) {
		vma = vma_lookup(current->mm, pc);
		if (!vma || !(vma->vm_flags & VM_EXEC) ||
		    (vma->vm_flags & VM_SHARED)) {
			mmap_read_unlock(current->mm);
			return false;
		}

		locked = 1;
		ret = get_user_pages_remote(current->mm, pc & PAGE_MASK, 1,
					    gup_flags, &page, &locked);
		if (locked)
			break;
		/* the mapping may have been replaced while the page faulted */
	}

	if (ret == 1) {
		folio = page_folio(page);
		kaddr = kmap_local_page(page);
		/*
		 * Whatever is at the site now is what runs next: anything but
		 * the instruction that trapped is somebody else's doing, and is
		 * left alone
		 */
		if (*(u32 *)(kaddr + offset_in_page(pc)) == insn) {
			copy_to_user_page(vma, page, pc, kaddr + offset_in_page(pc),
					  &replacement, sizeof(replacement));
			ret = 1;
		} else {
			ret = 0;
		}
		kunmap_local(kaddr);
	} else {
		folio = NULL;
	}
	mmap_read_unlock(current->mm);

	if (folio) {
		set_page_dirty_lock(page);
		folio_put(folio);
	}

	return ret == 1;
}

/*
 * The load the instruction asked for, made the way the task that faulted would
 * have made it: get_user() is the unprivileged load, and a fault the fault
 * handler can resolve is resolved before any error comes back
 */
static int rcpc_load(u32 insn, unsigned long addr, u64 *value)
{
	/* the narrower forms zero extend */
	*value = 0;

	switch (RCPC_SIZE(insn)) {
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
 * The signal the load would have taken: an address in a mapping that does not
 * allow the read is a protection fault, and one in no mapping at all is a
 * missing mapping
 */
static void rcpc_fault(unsigned long addr)
{
	struct vm_area_struct *vma;
	int code = SEGV_MAPERR;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, untagged_addr(addr));
	if (vma && !(vma->vm_flags & VM_READ))
		code = SEGV_ACCERR;
	mmap_read_unlock(current->mm);

	force_signal_inject(SIGSEGV, code, addr, 0);
}

/*
 * Performs the instruction an EL0 task was stopped on
 *
 * Returns false when it is not one of the RCpc loads: nothing has changed, and
 * the caller answers for the exception as it would have without this
 */
bool try_emulate_rcpc(struct pt_regs *regs, u32 insn)
{
	unsigned long addr;
	u64 value;

	/* AArch32 has no RCpc loads */
	if (compat_user_mode(regs))
		return false;

	if ((insn & RCPC_LDAPR_MASK) == RCPC_LDAPR_VALUE)
		addr = rcpc_base(regs, insn);
	else if ((insn & RCPC_LDAPUR_MASK) == RCPC_LDAPUR_VALUE)
		addr = rcpc_base(regs, insn) + rcpc_imm9(insn);
	else
		return false;

	atomic_long_inc(&rcpc_emul_traps);

	/*
	 * The load the instruction asked for can be made here, but an address
	 * the architecture refuses is not one of them: an unaligned Load-Acquire
	 * takes the Alignment fault before the load is reached
	 */
	if (!rcpc_unaligned_ok && !rcpc_aligned(insn, addr)) {
		force_signal_inject(SIGBUS, BUS_ADRALN, addr, 0);
		return true;
	}

	if (rcpc_rewrite(regs, insn))
		atomic_long_inc(&rcpc_emul_rewrites);

	if (rcpc_load(insn, addr, &value)) {
		/*
		 * The fault is the task's: report it at the address the
		 * instruction would have used, and leave the instruction where
		 * it is, as a load that faulted would have
		 */
		rcpc_fault(addr);
		return true;
	}

	/* Rt=31 discards the value, and regs->regs[31] is not a register */
	if (RCPC_RT(insn) != 31)
		regs->regs[RCPC_RT(insn)] = value;

	/*
	 * LDAPR orders later accesses after itself and says nothing about
	 * earlier ones, which is weaker than this barrier
	 */
	dmb(ishld);

	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);

	return true;
}

static int rcpc_emul_stats_show(struct seq_file *m, void *unused)
{
	seq_printf(m, "traps %lu\n", atomic_long_read(&rcpc_emul_traps));
	seq_printf(m, "rewrites %lu\n", atomic_long_read(&rcpc_emul_rewrites));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(rcpc_emul_stats);

static int rcpc_emul_rewrite_get(void *data, u64 *val)
{
	*val = rcpc_rewrite_enabled;

	return 0;
}

static int rcpc_emul_rewrite_set(void *data, u64 val)
{
	rcpc_rewrite_enabled = val;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(rcpc_emul_rewrite_fops, rcpc_emul_rewrite_get,
			 rcpc_emul_rewrite_set, "%llu\n");

static int __init rcpc_emul_init(void)
{
	u64 mmfr2 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);
	struct dentry *dir;

	rcpc_unaligned_ok =
		cpuid_feature_extract_unsigned_field(mmfr2,
						     ID_AA64MMFR2_EL1_AT_SHIFT) != 0;

	dir = debugfs_create_dir("rcpc_emul", NULL);
	debugfs_create_file("stats", 0444, dir, NULL, &rcpc_emul_stats_fops);
	debugfs_create_file("rewrite", 0644, dir, NULL, &rcpc_emul_rewrite_fops);

	return 0;
}
late_initcall(rcpc_emul_init);
