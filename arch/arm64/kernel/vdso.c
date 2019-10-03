/*
 * VDSO implementation for AArch64 and vector page setup for AArch32.
 *
 * Copyright (C) 2012 ARM Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <linux/kernel.h>
#include <linux/clocksource.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/timekeeper_internal.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/signal32.h>
#include <asm/vdso.h>
#include <asm/vdso_datapage.h>
#include <asm/compat.h>

extern char vdso_start, vdso_end;
static unsigned long vdso_pages;
static struct page **vdso_pagelist;

#ifdef CONFIG_ARM64_ILP32
extern char vdso_ilp32_start, vdso_ilp32_end;
static unsigned long vdso_ilp32_pages;
static struct page **vdso_ilp32_pagelist;
#endif

/*
 * The vDSO data page.
 */
static union {
	struct vdso_data	data;
	u8			page[PAGE_SIZE];
} vdso_data_store __page_aligned_data;
struct vdso_data *vdso_data = &vdso_data_store.data;

#ifdef CONFIG_AARCH32_EL0
/*
 * Create and map the vectors page for AArch32 tasks.
 */
static struct page *vectors_page[1];

static int alloc_vectors_page(void)
{
	extern char __kuser_helper_start[], __kuser_helper_end[];
	extern char __aarch32_sigret_code_start[], __aarch32_sigret_code_end[];

	int kuser_sz = __kuser_helper_end - __kuser_helper_start;
	int sigret_sz = __aarch32_sigret_code_end - __aarch32_sigret_code_start;
	unsigned long vpage;

	vpage = get_zeroed_page(GFP_ATOMIC);

	if (!vpage)
		return -ENOMEM;

	/* kuser helpers */
	memcpy((void *)vpage + 0x1000 - kuser_sz, __kuser_helper_start,
		kuser_sz);

	/* sigreturn code */
	memcpy((void *)vpage + AARCH32_KERN_SIGRET_CODE_OFFSET,
               __aarch32_sigret_code_start, sigret_sz);

	flush_icache_range(vpage, vpage + PAGE_SIZE);
	vectors_page[0] = virt_to_page(vpage);

	return 0;
}
arch_initcall(alloc_vectors_page);

int aarch32_setup_vectors_page(struct linux_binprm *bprm, int uses_interp)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr = AARCH32_VECTORS_BASE;
	static struct vm_special_mapping spec = {
		.name	= "[vectors]",
		.pages	= vectors_page,

	};
	void *ret;

	down_write(&mm->mmap_sem);
	current->mm->context.vdso = (void *)addr;

	/* Map vectors page at the high address. */
	ret = _install_special_mapping(mm, addr, PAGE_SIZE,
				       VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYEXEC,
				       &spec);

	up_write(&mm->mmap_sem);

	return PTR_ERR_OR_ZERO(ret);
}
#endif /* CONFIG_AARCH32_EL0 */

static struct vm_special_mapping vdso_spec[2][2];

static inline int __init vdso_init_common(char *vdso_start, char *vdso_end,
					  unsigned long *vdso_pagesp,
					  struct page ***vdso_pagelistp,
					  bool ilp32)
{
	int i;
	unsigned long vdso_pages;
	struct page **vdso_pagelist;

	if (memcmp(vdso_start, "\177ELF", 4)) {
		pr_err("vDSO is not a valid ELF object!\n");
		return -EINVAL;
	}

	vdso_pages = (vdso_end - vdso_start) >> PAGE_SHIFT;
	*vdso_pagesp = vdso_pages;
	pr_info("vdso: %ld pages (%ld code @ %p, %ld data @ %p)\n",
		vdso_pages + 1, vdso_pages, vdso_start, 1L, vdso_data);

	/* Allocate the vDSO pagelist, plus a page for the data. */
	vdso_pagelist = kcalloc(vdso_pages + 1, sizeof(struct page *),
				GFP_KERNEL);
	*vdso_pagelistp = vdso_pagelist;
	if (vdso_pagelist == NULL)
		return -ENOMEM;

	/* Grab the vDSO data page. */
	vdso_pagelist[0] = virt_to_page(vdso_data);

	/* Grab the vDSO code pages. */
	for (i = 0; i < vdso_pages; i++)
		vdso_pagelist[i + 1] = virt_to_page(vdso_start + i * PAGE_SIZE);

	/* Populate the special mapping structures */
	vdso_spec[ilp32][0] = (struct vm_special_mapping) {
		.name	= "[vvar]",
		.pages	= vdso_pagelist,
	};

	vdso_spec[ilp32][1] = (struct vm_special_mapping) {
		.name	= "[vdso]",
		.pages	= &vdso_pagelist[1],
	};

	return 0;
}

static int __init vdso_init(void)
{
	return vdso_init_common(&vdso_start, &vdso_end,
				&vdso_pages, &vdso_pagelist, 0);
}
arch_initcall(vdso_init);

#ifdef CONFIG_ARM64_ILP32
static int __init vdso_ilp32_init(void)
{
	return vdso_init_common(&vdso_ilp32_start, &vdso_ilp32_end,
				&vdso_ilp32_pages, &vdso_ilp32_pagelist, 1);
}
arch_initcall(vdso_ilp32_init);
#endif

int arch_setup_additional_pages(struct linux_binprm *bprm,
				int uses_interp)
{
	struct mm_struct *mm = current->mm;
	unsigned long vdso_base, vdso_text_len, vdso_mapping_len;
	void *ret;
	struct page **pagelist;
	unsigned long pages;
	bool ilp32;

#ifdef CONFIG_ARM64_ILP32
	ilp32 = is_ilp32_compat_task();
	if (is_ilp32_compat_task()) {
		pages = vdso_ilp32_pages;
		pagelist = vdso_ilp32_pagelist;
	} else
#endif
	{
		ilp32 = false;
		pages = vdso_pages;
		pagelist = vdso_pagelist;
	}
	vdso_text_len = pages << PAGE_SHIFT;
	/* Be sure to map the data page */
	vdso_mapping_len = (pages + 1) << PAGE_SHIFT;

	down_write(&mm->mmap_sem);
	vdso_base = get_unmapped_area(NULL, 0, vdso_mapping_len, 0, 0);
	if (IS_ERR_VALUE(vdso_base)) {
		ret = ERR_PTR(vdso_base);
		goto up_fail;
	}
	ret = _install_special_mapping(mm, vdso_base, PAGE_SIZE,
				       VM_READ|VM_MAYREAD,
				       &vdso_spec[ilp32][0]);
	if (IS_ERR(ret))
		goto up_fail;

	vdso_base += PAGE_SIZE;
	mm->context.vdso = (void *)vdso_base;
	ret = _install_special_mapping(mm, vdso_base, vdso_text_len,
				       VM_READ|VM_EXEC|
				       VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				       &vdso_spec[ilp32][1]);
	if (IS_ERR(ret))
		goto up_fail;


	up_write(&mm->mmap_sem);
	return 0;

up_fail:
	mm->context.vdso = NULL;
	up_write(&mm->mmap_sem);
	return PTR_ERR(ret);
}

/*
 * We define AT_SYSINFO_EHDR, so we need these function stubs to keep
 * Linux happy.
 */
int in_gate_area_no_mm(unsigned long addr)
{
	return 0;
}

int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
	return 0;
}

struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
	return NULL;
}

/*
 * Update the vDSO data page to keep in sync with kernel timekeeping.
 */
void update_vsyscall(struct timekeeper *tk)
{
	struct timespec xtime_coarse;
	u32 use_syscall = strcmp(tk->clock->name, "arch_sys_counter");

	++vdso_data->tb_seq_count;
	smp_wmb();

	xtime_coarse = __current_kernel_time();
	vdso_data->use_syscall			= use_syscall;
	vdso_data->xtime_coarse_sec		= xtime_coarse.tv_sec;
	vdso_data->xtime_coarse_nsec		= xtime_coarse.tv_nsec;
	vdso_data->wtm_clock_sec		= tk->wall_to_monotonic.tv_sec;
	vdso_data->wtm_clock_nsec		= tk->wall_to_monotonic.tv_nsec;

	if (!use_syscall) {
		vdso_data->cs_cycle_last	= tk->clock->cycle_last;
		vdso_data->xtime_clock_sec	= tk->xtime_sec;
		vdso_data->xtime_clock_nsec	= tk->xtime_nsec;
		vdso_data->cs_mult		= tk->mult;
		vdso_data->cs_shift		= tk->shift;
	}

	smp_wmb();
	++vdso_data->tb_seq_count;
}

void update_vsyscall_tz(void)
{
	vdso_data->tz_minuteswest	= sys_tz.tz_minuteswest;
	vdso_data->tz_dsttime		= sys_tz.tz_dsttime;
}
