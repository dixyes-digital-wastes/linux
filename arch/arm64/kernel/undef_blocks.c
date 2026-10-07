// SPDX-License-Identifier: GPL-2.0-only
/*
 * The blocks the LSE atomic sites are replaced with
 *
 * A site that traps every time it runs is worth a branch and a few
 * instructions instead, so it is sent to a block that makes the operation with
 * the exclusive pair and branches back to the instruction after it. The block
 * is placed where a branch reaches it, says everything about itself that a
 * fault inside it needs to be answered with, and anything that keeps it from
 * finishing is taken back to the emulation of the instruction
 *
 * The pages are the task's own anonymous mappings, so one that forks keeps its
 * blocks in its own copy of them, and a block that is changed out of what it
 * was made as faults, which is answered by the instruction itself
 */

#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/mmap_lock.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/esr.h>
#include <asm/insn-def.h>
#include <asm/ptrace.h>
#include <asm/traps.h>

#include "lse_block_code.h"

/* How much of a page one block may use, and how many of them fit in one */
#define LSE_BLOCK_SIZE		128
#define LSE_BLOCK_SLOTS		(PAGE_SIZE / LSE_BLOCK_SIZE)

/* The reach of the branch a site is replaced with */
#define LSE_BLOCK_RANGE		BIT(27)

/*
 * What a block says about itself at the start of its slot: the instruction it
 * stands for and where that is, what it holds in the frame it pushes, and the
 * instructions that make the operation
 */
struct lse_block {
	u64	site;
	u32	saved;
	u32	frame;
	u32	insn;
	u32	count;
	u32	reserved[2];
	u32	code[(LSE_BLOCK_SIZE - LSE_BLOCK_CODE) / sizeof(u32)];
};

static_assert(sizeof(struct lse_block) == LSE_BLOCK_SIZE);
static_assert(offsetof(struct lse_block, code) == LSE_BLOCK_CODE);

/* The blocks that could not finish and were answered by the emulation */
static atomic_long_t lse_block_faults;

unsigned long lse_block_fault_count(void)
{
	return atomic_long_read(&lse_block_faults);
}

/* A slot with nothing in it holds no site */
static bool lse_block_free(const struct lse_block *block)
{
	return !block->site;
}

/*
 * What a page of blocks is marked with: the offset of a private anonymous
 * mapping says nothing about it, and a page that is marked this way is still
 * an anonymous page in every other way, faults included
 */
#define LSE_BLOCK_MAGIC		0x1e5e1e5e

static bool lse_block_vma(const struct vm_area_struct *vma)
{
	return vma->vm_pgoff == LSE_BLOCK_MAGIC && vma_is_anonymous(vma) &&
	       (vma->vm_flags & (VM_DONTEXPAND | VM_DONTDUMP)) ==
	       (VM_DONTEXPAND | VM_DONTDUMP);
}

/* A page of blocks the kernel can write in, and the mapping that page is in */
struct lse_block_page {
	struct folio	*folio;
	struct page	*page;
	void		*kaddr;
};

/* The page of blocks that already serves the site, if there is one */
static unsigned long lse_block_find(struct mm_struct *mm, unsigned long site)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma;
	unsigned long page = 0;

	mmap_read_lock(mm);
	for_each_vma(vmi, vma) {
		if (!lse_block_vma(vma))
			continue;
		if (site - vma->vm_start + LSE_BLOCK_RANGE >= 2 * LSE_BLOCK_RANGE)
			continue;
		page = vma->vm_start;
		break;
	}
	mmap_read_unlock(mm);

	return page;
}

/*
 * A new page of blocks for the site
 *
 * The mapping is the task's to place, so it is asked for near the site and it
 * is the mm that decides where: a page that ends up out of reach of the branch
 * is one no block is put in
 */
static unsigned long lse_block_new(struct mm_struct *mm, unsigned long site)
{
	struct vm_area_struct *vma;
	unsigned long page;

	/*
	 * The mapping is the task's to place, so it is asked for half a window
	 * away from the site: a page put beside it would be a page in the space
	 * the heap and the loader grow into, and one the mm puts out of reach
	 * of the branch is a page no block is put in
	 */
	page = vm_mmap(NULL, (site + LSE_BLOCK_RANGE / 2) & PAGE_MASK, PAGE_SIZE,
		       PROT_READ | PROT_WRITE | PROT_EXEC,
		       MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE(page))
		return 0;

	if (page - site + LSE_BLOCK_RANGE >= 2 * LSE_BLOCK_RANGE) {
		vm_munmap(page, PAGE_SIZE);
		return 0;
	}

	/* the page is only one of ours once it says so */
	mmap_write_lock(mm);
	vma = vma_lookup(mm, page);
	if (vma && vma->vm_start == page && vma_is_anonymous(vma)) {
		vma->vm_pgoff = LSE_BLOCK_MAGIC;
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	} else {
		page = 0;
	}
	mmap_write_unlock(mm);

	return page;
}

static int lse_block_map(struct mm_struct *mm, unsigned long page,
			 struct lse_block_page *mapped)
{
	unsigned int gup_flags = FOLL_WRITE | FOLL_FORCE | FOLL_SPLIT_PMD;
	int locked = 1;

	if (get_user_pages_remote(mm, page, 1, gup_flags, &mapped->page,
				  &locked) != 1)
		return -EFAULT;
	if (!locked)
		return -EAGAIN;

	mapped->folio = page_folio(mapped->page);
	mapped->kaddr = kmap_local_page(mapped->page);

	return 0;
}

static void lse_block_unmap(struct lse_block_page *mapped, bool dirty)
{
	kunmap_local(mapped->kaddr);
	if (dirty)
		set_page_dirty_lock(mapped->page);
	folio_put(mapped->folio);
}

/* What a task's own block page holds, without touching the mapping */
static int lse_block_peek(struct mm_struct *mm, unsigned long addr,
			  struct lse_block *block)
{
	struct vm_area_struct *vma;

	vma = vma_lookup(mm, addr);
	if (!vma || !lse_block_vma(vma))
		return -EFAULT;

	if (copy_from_user(block, (void __user *)addr, sizeof(*block)))
		return -EFAULT;

	return 0;
}

/*
 * Puts a block in place for a site, and sends the site to it
 *
 * The instruction the site holds is what is patched over, and only where it is
 * still the one that trapped: anything else at the site is somebody else's and
 * is left alone, with the block left unused
 */
bool lse_block_install(struct pt_regs *regs, u32 insn, unsigned long site,
		       unsigned int saved, unsigned int frame,
		       const u32 *code, unsigned int count)
{
	struct mm_struct *mm = current->mm;
	struct lse_block_page mapped;
	struct lse_block *block;
	struct vm_area_struct *vma;
	unsigned long page, addr = 0;
	unsigned int slot;
	bool placed = false;
	u32 branch;
	int ret = 0;

	if (!mm || site != instruction_pointer(regs))
		return false;

	block = kzalloc_obj(*block);
	if (!block)
		return false;

	page = lse_block_find(mm, site);
	if (!page)
		page = lse_block_new(mm, site);

	while (page && !placed) {
		mmap_read_lock(mm);
		vma = vma_lookup(mm, page);
		if (!vma || !lse_block_vma(vma)) {
			mmap_read_unlock(mm);
			break;
		}

		ret = lse_block_map(mm, page, &mapped);
		if (ret) {
			mmap_read_unlock(mm);
			break;
		}
		for (slot = 0; slot < LSE_BLOCK_SLOTS; slot++) {
			addr = page + slot * LSE_BLOCK_SIZE;
			if (!lse_block_free((void *)mapped.kaddr +
					    slot * LSE_BLOCK_SIZE))
				continue;

			block->site = site;
			block->saved = saved;
			block->frame = frame;
			block->insn = insn;
			block->count = count;
			memcpy(block->code, code, count * sizeof(*code));
			block->code[count - 1] = lse_back(site, addr, count);
			copy_to_user_page(vma, mapped.page, addr,
					  mapped.kaddr + slot * LSE_BLOCK_SIZE,
					  block, sizeof(*block));
			placed = true;
			break;
		}

		lse_block_unmap(&mapped, placed);
		mmap_read_unlock(mm);
		if (slot == LSE_BLOCK_SLOTS)
			break;		/* the page is full: the site keeps trapping */
	}

	/* the site only goes to the block where the branch back is in its mapping */
	if (placed) {
		mmap_read_lock(mm);
		vma = vma_lookup(mm, site);
		placed = vma && site + AARCH64_INSN_SIZE <= vma->vm_end;
		mmap_read_unlock(mm);
	}

	if (placed) {
		/*
		 * The site goes to the code of the block, not to what it says
		 * about itself
		 */
		branch = lse_offset(LSE_B, ((long)addr + LSE_BLOCK_CODE -
					   (long)site) / 4);
		placed = undef_patch_text(regs, insn, branch);
	}
	kfree(block);

	return placed;
}

/*
 * Whether a fault was taken from inside a block, and what is left to do about
 * it
 *
 * A block that faulted on its way to the store has not made the operation, so
 * the instruction is carried out here with the registers the task had, which
 * the frame the block pushed holds
 *
 * Everything else the block is stopped by is the fault handler's: the page the
 * block is on is one this kernel made, and a fault on it that the handler can
 * resolve is answered by running the block again. The one that is the task's is
 * the branch the block ends with, which is the instruction after the site and
 * is reported there
 */
bool lse_block_fault(unsigned long esr, struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);
	unsigned long base = pc & ~(LSE_BLOCK_SIZE - 1);
	unsigned long sp = regs->sp;
	struct vm_area_struct *vma;
	struct lse_block *block;
	unsigned int i;

	if (!user_mode(regs))
		return false;

	mmap_read_lock(current->mm);
	vma = vma_lookup(current->mm, base);
	mmap_read_unlock(current->mm);
	if (!vma || !lse_block_vma(vma))
		return false;

	block = kmalloc_obj(*block);
	if (!block)
		return false;
	if (lse_block_peek(current->mm, base, block) || lse_block_free(block)) {
		kfree(block);
		return false;
	}

	/*
	 * A fault after the store is the branch back to the instruction after
	 * the site, which is where the task would have faulted, and the frame
	 * has been taken off by then
	 */
	if (ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW) {
		unsigned long back = base + LSE_BLOCK_CODE +
				     (block->count - 1) * sizeof(u32);

		/*
		 * Only the branch the block ends with is the task's: any
		 * other instruction of the block is one the fault handler
		 * answers for, and running the block again is the answer
		 */
		if (pc != back) {
			kfree(block);
			return false;
		}
		regs->pc = block->site + AARCH64_INSN_SIZE;
		undef_fault(regs->pc, VM_EXEC);
		kfree(block);
		return true;
	}

	/*
	 * The frame is one store, so a fault on it is a fault before anything
	 * of the block has happened: what the task had is still what it has,
	 * and the emulation is left to answer for the instruction
	 */
	if (pc != base + LSE_BLOCK_CODE) {
		for (i = 0; i < 31; i++) {
			u64 value;

			if (!(block->saved & BIT(i)))
				continue;
			if (get_user(value, (u64 __user *)sp))
				break;
			regs->regs[i] = value;
			sp += sizeof(u64);
		}
		regs->sp += block->frame;
	}

	regs->pc = block->site;
	atomic_long_inc(&lse_block_faults);
	if (!try_emulate_lse(regs, block->insn)) {
		kfree(block);
		return false;
	}
	kfree(block);

	return true;
}
