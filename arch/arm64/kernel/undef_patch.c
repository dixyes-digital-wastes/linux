// SPDX-License-Identifier: GPL-2.0-only
/*
 * Replacing the instruction an EL0 task was stopped on, and what the
 * emulations of the undefined instructions share
 *
 * An emulation that puts something else in the place of the instruction
 * writes into the task's own text, and one that carries the instruction out
 * has to report the faults it cannot resolve the way the instruction would
 * have. A processor that ran a line of that text which is no longer what the
 * site holds is given the site again
 */

#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/insn-def.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>
#include <asm/traps.h>

/* How many times a fault that takes the lock away is retried */
#define UNDEF_PATCH_TRIES	8

/*
 * Whether an unaligned atomic access is allowed here, which is what
 * ID_AA64MMFR2_EL1.AT reports: without ARMv8.4-LSE, an atomic access and a
 * non-atomic Load-Acquire or Store-Release take an Alignment fault when the
 * address is not aligned to the size of the access
 */
bool undef_unaligned_ok __ro_after_init;

/*
 * Whether the access an instruction makes at this address is aligned. The
 * size of every access that reaches here is in the two top bits, 1, 2, 4 or 8
 * bytes
 */
bool undef_aligned(u32 insn, unsigned long addr)
{
	switch (insn >> 30) {
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
 * The signal the access would have taken: an address in a mapping that does
 * not allow it is a protection fault, and one in no mapping at all is a
 * missing mapping
 *
 * The flags are what the access needs of the mapping: a load reads, an atomic
 * operation reads and writes
 */
void undef_fault(unsigned long addr, unsigned long flags)
{
	struct vm_area_struct *vma;
	int code = SEGV_MAPERR;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, untagged_addr(addr));
	if (vma && (vma->vm_flags & flags) != flags)
		code = SEGV_ACCERR;
	mmap_read_unlock(current->mm);

	force_signal_inject(SIGSEGV, code, addr, 0);
}

/*
 * Replaces the instruction a task was stopped on with one that takes over its
 * work, so that the next time it runs there is nothing to trap on
 *
 * What is written is the task's own copy of the page: a private mapping is
 * given one first, and a shared mapping is left alone, because the change
 * would be seen by every process that maps it. Whether the site still holds
 * the instruction that trapped is checked first, so an instruction somebody
 * else put there is not overwritten
 *
 * Whether this succeeds or not, the caller carries the instruction out, so
 * nothing depends on it but speed
 */
bool undef_patch_text(struct pt_regs *regs, u32 insn, u32 replacement)
{
	unsigned long pc = instruction_pointer(regs);
	unsigned int gup_flags = FOLL_WRITE | FOLL_FORCE | FOLL_SPLIT_PMD;
	struct vm_area_struct *vma;
	struct folio *folio;
	struct page *page = NULL;
	bool patched = false;
	void *kaddr;
	int locked;
	int tries;
	long ret;

	mmap_read_lock(current->mm);
	for (tries = 0; tries < UNDEF_PATCH_TRIES; tries++) {
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

		/*
		 * The lock is dropped around the fault that makes the page
		 * writable, and a signal taken while it faults can leave it
		 * dropped: that is what handing back unlocked as zero says.
		 * Take it again, because the mapping above is only good
		 * under it, and give up rather than spin if it keeps
		 * happening
		 */
		mmap_read_lock(current->mm);
	}

	if (tries == UNDEF_PATCH_TRIES) {
		mmap_read_unlock(current->mm);

		return false;
	}

	if (ret == 1) {
		folio = page_folio(page);
		kaddr = kmap_local_page(page);
		if (*(u32 *)(kaddr + offset_in_page(pc)) == insn) {
			copy_to_user_page(vma, page, pc, kaddr + offset_in_page(pc),
					  &replacement, sizeof(replacement));
			patched = true;
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

	return patched;
}

/*
 * Leaves the site to run again for a processor whose fetch of it was stale: the
 * line it ran is not what the site holds now, so that line is dropped here and
 * the instruction is left to be fetched again
 */
void undef_run_again(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	caches_clean_inval_user_pou(pc, pc + AARCH64_INSN_SIZE);
}

static int __init undef_patch_init(void)
{
	u64 mmfr2 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);

	undef_unaligned_ok =
		cpuid_feature_extract_unsigned_field(mmfr2,
						     ID_AA64MMFR2_EL1_AT_SHIFT) != 0;

	return 0;
}
late_initcall(undef_patch_init);
