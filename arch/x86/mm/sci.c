// SPDX-License-Identifier: GPL-2.0
//mutateOS core implementation

#include "asm/msr.h"
#include "asm/pgtable_types.h"
#include "linux/delay.h"
#include "linux/list.h"
#include "linux/llist.h"
#include "linux/pid.h"
#include "linux/printk.h"
#include "linux/rbtree.h"
#include "linux/rbtree_augmented.h"
#include "linux/spinlock.h"
#include "linux/spinlock_types.h"
#include "linux/vmalloc.h"
#include "linux/workqueue.h"
#include "linux/syscalls.h"
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/sizes.h>
#include <linux/sci.h>
#include <linux/random.h>
#include <linux/atomic.h>

#include <asm/special_insns.h>
#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/cmdline.h>
#include <asm/pgtable.h> //swapper_pg_dir存在
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/traps.h>
#include <asm/insn.h> //insn_init, insn_get_length

unsigned mutant_debug_level = MUTANT_ERR | MUTANT_INFO | MUTANT_DEBUG;

#undef pr_fmt
#define pr_fmt(fmt) "SCI: " fmt

#define JUMP_LEN (5)

__visible DEFINE_PER_CPU_PAGE_ALIGNED(struct sci_percpu_data, cpu_sci);

struct mm_struct *root_mm = &init_mm;

struct mm_struct *mutant_rootmm;

unsigned long PV_PERCPU_START;

unsigned long PV_PER_CPU_SLOT_LEN;

/*
 * Walk the shadow copy of the page tables to PMD level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Allocation failures are not handled here because the entire page
 * table will be freed in sci_free_pagetable.
 *
 * Returns a pointer to a PMD on success, or NULL on failure.
 */
static noinline pmd_t *sci_pagetable_walk_pmd(struct mm_struct *mm, pgd_t *pgd,
					      unsigned long address)
{
	p4d_t *p4d;
	pud_t *pud;
	
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return NULL;

	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		return NULL;

	return pmd_alloc(mm, pud, address);
}

/*
 * Walk the shadow copy of the page tables to PTE level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static noinline pte_t *sci_pagetable_walk_pte(struct mm_struct *mm, pgd_t *pgd,
					      unsigned long address)
{
	pmd_t *pmd = sci_pagetable_walk_pmd(mm, pgd, address);

	if (!pmd)
		return NULL;

	if (__pte_alloc(mm, pmd))
		return NULL;

	return pte_offset_kernel(pmd, address);
}

/*
 * Clone a single page mapping
 */
//缺页补页时候使用，每次仅仅补一个单页
static pte_t *sci_clone_page_for_pagefault(struct mm_struct *mm, pgd_t *pgdp,
					   pgd_t *target_pgdp,
					   unsigned long addr)
{
	pte_t *pte, *target_pte, ptev;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_pgd(pgdp, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	target_pgd = pgd_offset_pgd(target_pgdp, addr);

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pfn;

		/*
		 * We map only PAGE_SIZE rather than the entire huge page.
		 * The PTE will have the same pgprot bits as the origial PMD
		 */
		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		pfn = pmd_pfn(*pmd) + pte_index(addr); //找到原本存放内核代码的4M大页的其中一个对应分页，将这个页映射进入隔离页表
		ptev = pfn_pte(pfn, flags); //组装成一个pte项，包括了页物理地址与权限
	} else {
		pte = pte_offset_kernel(pmd, addr);
		if (pte_none(*pte) || !(pte_flags(*pte) & _PAGE_PRESENT))
			return NULL;

		ptev = *pte;
	}

	target_pte = sci_pagetable_walk_pte(mm, target_pgd, addr);
	if (!target_pte)
		return NULL;

	ptev = pte_clear_flags(ptev, _PAGE_ACCESSED);
	*target_pte = ptev;

	return target_pte;
}

static noinline int sci_clone_range_as_page(struct mm_struct *mm, pgd_t *pgdp,
					    pgd_t *target_pgdp,
					    unsigned long start,
					    unsigned long end)
{
	unsigned long addr;

	/*
	 * Clone the populated PMDs which cover start to end. These PMD areas
	 * can have holes.
	 */
	for (addr = start; addr < end;) {
		sci_clone_page_for_pagefault(mm, pgdp, target_pgdp, addr);
		addr = addr + PAGE_SIZE;
	}

	return 0;
}

static noinline int sci_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *ptep = pte_offset_kernel(pmd, 0);

	pmd_clear(pmd);
	pte_free(mm, virt_to_page(ptep));
	mm_dec_nr_ptes(mm);

	return 0;
}

static noinline int sci_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++)
		if (!pmd_none(*pmd) && !pmd_large(*pmd))
			sci_free_pte_range(mm, pmd);

	pud_clear(pud);
	pmd_free(mm, pmdp);
	mm_dec_nr_pmds(mm);

	return 0;
}

static noinline int sci_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++)
		if (!pud_none(*pud))
			sci_free_pmd_range(mm, pud);

	p4d_clear(p4d);
	pud_free(mm, pudp);
	mm_dec_nr_puds(mm);

	return 0;
}

static noinline int sci_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++)
		if (!p4d_none(*p4d))
			sci_free_pud_range(mm, p4d);

	pgd_clear(pgd);
	p4d_free(mm, p4dp);

	return 0;
}

static int sci_free_pagetable(struct mm_struct *mm, pgd_t *sci_pgd)
{
	pgd_t *pgd, *pgdp = sci_pgd;
	int i;

	for (i = pgd_index(0xffffffff00000000); i < PTRS_PER_PGD; i++) {
		pgd = pgdp + i;
		if (!pgd_none(*pgd))
			sci_free_p4d_range(mm, pgd);
	}

	return 0;
}

//used for stack copy in VMALLOC
static void sci_clone_vmalloc_as_pagefault(pgd_t *sci_pgd)
{
	pgd_t *pgd, *pgd_k;
	int i;

	for (i = pgd_index(VMALLOC_START); i <= pgd_index(VMALLOC_END); i++) {
		pgd = sci_pgd + i;
		pgd_k = root_mm->pgd + i;
		if (!pgd_none(*pgd))
			set_pgd(pgd, *pgd_k);
	}

	return;
}

static void mutant_clone_pgtable_pgd(pgd_t *sci_pgd,
					      pgd_t *template_pgd,
					      unsigned long start,
					      unsigned long end)
{
	pgd_t *pgd, *pgd_k;
	int i;

	for (i = pgd_index(start); i <= pgd_index(end); i++) {
		pgd = sci_pgd + i;
		pgd_k = template_pgd + i;
		if (!pgd_none(*pgd))
			set_pgd(pgd, *pgd_k);
	}

	return;
}

static int sci_pagetable_init(struct sci_task_data *sci)
{
	struct mm_struct *mm = sci->mm;
	pgd_t *sci_pgd = sci->mm->pgd;
	pgd_t *k_pgd = root_mm->pgd; //swapper_pg_dir
	int ret = 0;

	if (pgtable_l5_enabled()) {
		mutant_clone_pgtable_pgd(sci_pgd, root_mm->pgd,
					 0xff00000000000000,
					 0xff10ffffffffffff);

		mutant_clone_pgtable_pgd(sci_pgd, mutant_rootmm->pgd,
					 0xff11000000000000,
					 0xff90ffffffffffff);

		mutant_clone_pgtable_pgd(sci_pgd, root_mm->pgd,
					 0xff91000000000000,
					 PRIVATE_VMALLOC_START - 1);
		mutant_clone_pgtable_pgd(sci_pgd, root_mm->pgd,
					 PRIVATE_VMALLOC_END + 1,
					 0xffffff7fffffffff);
	} else {
		mutant_clone_pgtable_pgd(sci_pgd, root_mm->pgd,
					 0xffff800000000000,
					 0xffff887fffffffff);

		// direct memory map region
		mutant_clone_pgtable_pgd(sci_pgd, mutant_rootmm->pgd,
					 0xffff888000000000,
					 0xffffc87fffffffff);

		// vmalloc region
		mutant_clone_pgtable_pgd(sci_pgd, root_mm->pgd,
					 0xffffc88000000000,
					 PRIVATE_VMALLOC_START - 1);
		mutant_clone_pgtable_pgd(sci_pgd, root_mm->pgd,
					 PRIVATE_VMALLOC_END + 1,
					 0xffffff7fffffffff);
	}

	ret = sci_clone_range_as_page(mm, k_pgd, sci_pgd, __START_KERNEL_map,
				      (u64)__priviledged_text_start);
	if (ret)
		goto err;
		
	ret = sci_clone_range_as_page(mm, k_pgd, sci_pgd, (u64)__priviledged_text_end,
				      0xffffffffff600fff);
	if (ret)
		goto err;

	return ret;

err:
	sci_free_pagetable(mm, sci_pgd);
	return ret;
}

//返回一个新分配的页的虚拟地址，不创建大页,返回其虚拟地址
static unsigned long
sci_map_new_page(struct sci_task_data *sci, pgprot_t flags, unsigned long addr)
{
	pte_t *target_pte;
	pgd_t *target_pgd;
	unsigned long newpage_address; //新分配的页的虚拟地址
	unsigned long pfn; //新分配页的物理地址

	target_pgd = pgd_offset_pgd(sci->mm->pgd, addr);
	target_pte = sci_pagetable_walk_pte(sci->mm, target_pgd, addr);
	if (!target_pte)
		return 0;

	newpage_address = get_zeroed_page(GFP_KERNEL);
	if (!newpage_address)
		return 0;

	pfn = page_to_pfn(virt_to_page((void *)newpage_address));
	//将新分配的页连同其只读权限都写入隔离页表
	*target_pte = pfn_pte(pfn, flags);
	return newpage_address;
}

/*实现inlinehook基本功能，每次为一个sci_probe结构体设置好需要替换的指令
 *主要填写sci_probe结构体中的：
 *char save_ip[15] 	桩函数处所需写入的内容：JMP指令+原本的第一二条指令
 *char jump_ip[15]	待替换的原函数处所需要写入的指令内容：JMP指令
 *int save_len	
*/
int __priviledged sci_inline_hook_ins_make(struct sci_probe *hook)
{
	int ret = 0;
	struct insn ins;
	int len = 0;
	int *tmp = 0;
	char *tmp1 = NULL;

	/* jump offset */
	(hook->jump_ip)[0] = 0xe9;
	tmp = (int *)&(hook->jump_ip)[1];

	/*offset = to_ip - (from_ip+JUMP_LEN)  */
	*tmp = (unsigned long)(hook->new_func) -
	       ((unsigned long)(hook->orig_func) + JUMP_LEN);

	/* Get first instrucion len*/
	while (ret < JUMP_LEN) {
		insn_init(&ins, (hook->orig_func) + ret, 15, 1);
		insn_get_length(&ins);
		ret += ins.length;
	}

	len = ret;
	//向save_ip中拷贝原本函数开头的指令
	memcpy(hook->save_ip, hook->orig_func, len);
	tmp1 = (char *)(hook->orig_func);

	ret = ((unsigned long)(hook->orig_func) + len) -
	      ((unsigned long)(hook->stub_func) + JUMP_LEN + len);
	(hook->save_ip)[len] = 0xe9;
	tmp = (int *)&(hook->save_ip)[len + 1];
	*tmp = ret;

	hook->save_len = len;

	return 0;
}

//因为JMP指令跨页，所以需要替换两个物理页
static inline void sci_add_cross_page_probe(struct sci_task_data *sci,
					    struct sci_probe *probe)
{
	unsigned long addr = (unsigned long)probe->orig_func;
	unsigned long offset = offset_in_page(addr);
	int len = (int)(PAGE_SIZE - offset);

	//在虚拟地址addr处分配并挂载一个新的空白物理页
	probe->pfn_vaddr1 = sci_map_new_page(sci, PAGE_KERNEL_EXEC, addr);
	probe->pfn_vaddr2 =
		sci_map_new_page(sci, PAGE_KERNEL_EXEC, addr + JUMP_LEN);

	//复制页中原本的内容
	memcpy((void *)probe->pfn_vaddr1, (void *)(PAGE_MASK & addr),
	       PAGE_SIZE);
	memcpy((void *)probe->pfn_vaddr2,
	       (void *)(PAGE_MASK & addr) + PAGE_SIZE, PAGE_SIZE);
	//复制JMP指令
	memcpy((void *)(probe->pfn_vaddr1 + offset), probe->jump_ip,
	       len);
	memcpy((void *)probe->pfn_vaddr2, &probe->jump_ip[len],
	       JUMP_LEN - len);
}

static inline void sci_add_nocross_page_probe(struct sci_task_data *sci,
					      struct sci_probe *probe)
{
	unsigned long addr = (unsigned long)probe->orig_func;
	unsigned long offset = offset_in_page(addr);

	probe->pfn_vaddr1 = sci_map_new_page(sci, PAGE_KERNEL_EXEC, addr);
	probe->pfn_vaddr2 = 0;

	memcpy((void *)probe->pfn_vaddr1, (void *)(PAGE_MASK & addr),
	       PAGE_SIZE);

	memcpy((void *)(probe->pfn_vaddr1 + offset), (void *)probe->jump_ip,
	       JUMP_LEN);
}

/*第一个最简单的版本：将当前页的所有内容都原封不动的写进去，并在函数的入口处写入跳转指令
*将执行流跳转到模块中
页表权限：不是全局页，需要在每次进程切换时刷新掉，以防止其他进程走到这个虚拟地址的时候看
到这个页
*/
static bool sci_add_probe_page(struct sci_task_data *sci,
					struct sci_probe *probe)
{
	unsigned long addr;
	unsigned long offset;
	bool cross_page_boundary;

	sci_inline_hook_ins_make(probe);

	//待修改的函数的地址
	addr = (unsigned long)probe->orig_func;
	offset = offset_in_page(addr);
	//判断指令是否跨页
	cross_page_boundary = offset + JUMP_LEN > PAGE_SIZE;

	if (cross_page_boundary)
		sci_add_cross_page_probe(sci, probe);
	else
		sci_add_nocross_page_probe(sci, probe);

	return true;
}

/*sci的对外接口：实现针对sci页表的函数替换探针
* 内核模块只需要实现一个sci_probe结构体，
* 并在其中填入想要替换的函数名与要换上的对应函数实现
* 需要在sci结构体初始化完成后调用此函数
* 没有对应的unregister函数，随着sci_exit自动销毁
*/
int __priviledged sci_register_probe(struct sci_probe *p, struct sci_task_data *sci)
{
	unsigned long addr;

	if (!sci || sci->probelist_len >= SCI_MAX_PROBLIST || !p->name || !p->new_func)
		return 0;

	addr = kallsyms_lookup_name(p->name);
	if (!addr)
		return 0;

	p->orig_func = (void *)addr;

	sci->probelist[sci->probelist_len] = p;

	sci->probelist_len++;

	sci_add_probe_page(sci, p);

	return 1;
}
EXPORT_SYMBOL(sci_register_probe);

static struct sci_probe_page *
sci_add_one_parameter_page(unsigned long addr, struct sci_task_data *sci)
{
	struct sci_probe_page *used_page = NULL;
	int i;
	for (i = 0; i < sci->parameterlist_len; i++) {
		if (addr == sci->parameterlist[i]->pg_vaddr1) {
			used_page = sci->parameterlist[i]->new_page1;
			break;
		}
		if (addr == sci->parameterlist[i]->pg_vaddr2) {
			used_page = sci->parameterlist[i]->new_page2;
			break;
		}
	}

	if (used_page) {
		used_page->used_count++;
	}
	return used_page;
}

static inline struct sci_probe_page *
sci_get_one_new_ro_param_page(struct sci_task_data *sci, unsigned long addr)
{
	struct sci_probe_page *new_page =
		kzalloc(sizeof(struct sci_probe_page), GFP_KERNEL);
	new_page->pfn_vaddr = sci_map_new_page(sci, PAGE_KERNEL_RO, addr);
	new_page->used_count = 1;

	//复制页中原本的内容
	memcpy((void *)new_page->pfn_vaddr, (void *)(PAGE_MASK & addr),
	       PAGE_SIZE);

	return new_page;
}

static inline void
sci_add_cross_page_new_parameter_page(struct sci_task_data *sci,
				      struct sci_new_parameter *p)
{
	unsigned long addr = (unsigned long)p->orig_addr;
	unsigned long offset = offset_in_page(addr);
	int len = (int)(PAGE_SIZE - offset);

	struct sci_probe_page *used_page =
		sci_add_one_parameter_page(PAGE_MASK & addr, sci);
	p->new_page1 = used_page ? used_page :
				   sci_get_one_new_ro_param_page(sci, addr);
	p->pg_vaddr1 = PAGE_MASK & addr;

	addr += p->origin_para_size;
	used_page = sci_add_one_parameter_page(PAGE_MASK & addr, sci);
	p->new_page2 = used_page ? used_page :
				   sci_get_one_new_ro_param_page(sci, addr);
	p->pg_vaddr2 = p->pg_vaddr1 + PAGE_SIZE;

	//复制parameter
	memcpy((void *)(p->new_page1->pfn_vaddr + offset), (void *)p->content,
	       len);
	memcpy((void *)p->new_page2->pfn_vaddr, (void *)(p->content + len),
	       p->origin_para_size - len);
}

static inline void
sci_add_nocross_page_new_parameter_page(struct sci_task_data *sci,
					struct sci_new_parameter *p)
{
	unsigned long addr = (unsigned long)p->orig_addr;
	unsigned long offset = offset_in_page(addr);
	unsigned long pfn_vaddr;

	struct sci_probe_page *used_page =
		sci_add_one_parameter_page(PAGE_MASK & addr, sci);
	if (used_page)
		pfn_vaddr = used_page->pfn_vaddr;
	else {
		p->new_page1 = used_page ?
				       used_page :
				       sci_get_one_new_ro_param_page(sci, addr);
		pfn_vaddr = p->new_page1->pfn_vaddr;
	}
	p->pg_vaddr1 = PAGE_MASK & addr;
	p->new_page2 = NULL;
	p->pg_vaddr2 = 0;

	//复制parameter
	memcpy((void *)(pfn_vaddr + offset), (void *)p->content,
	       p->origin_para_size);
}

//页表权限：不是全局页，需要在每次进程切换时刷新掉，
//以防止其他进程走到这个虚拟地址的时候看到这个页
static bool sci_add_new_parameter_page(struct sci_task_data *sci,
						struct sci_new_parameter *p)
{
	//待修改parameter的地址
	unsigned long addr = (unsigned long)p->orig_addr;
	unsigned long offset = offset_in_page(addr);
	//判断指令是否跨页
	bool cross_page_boundary = offset + p->origin_para_size > PAGE_SIZE;

	if (cross_page_boundary)
		sci_add_cross_page_new_parameter_page(sci, p);
	else
		sci_add_nocross_page_new_parameter_page(sci, p);

	return true;
}

/*sci的对外接口：实现针对sci页表的参数定制替换
* 内核模块只需要实现一个sci_new_parameter结构体，
* 并在其中填入想要替换的函数名与要换上的对应函数实现
* 需要在sci结构体初始化完成后调用此函数
* 没有对应的unregister函数，随着sci_exit自动销毁
*/
int __priviledged sci_modify_parameter(struct sci_new_parameter *p, struct sci_task_data *sci)
{
	unsigned long addr;
	char namebuf[KSYM_NAME_LEN];
	unsigned long offset, size;
	char *modname;

	if (!sci || sci->parameterlist_len >= SCI_MAX_PARAMETERLIST || !p->name || !p->content)
		return 0;

	addr = kallsyms_lookup_name(p->name);
	if (!addr)
		return 0;

	kallsyms_lookup(addr, &size, &offset, &modname, namebuf);

	p->origin_para_size = size;
	p->orig_addr = (void *)addr;

	sci->parameterlist[sci->parameterlist_len] = p;

	sci->parameterlist_len++;

	sci_add_new_parameter_page(sci, p);

	return 1;
}
EXPORT_SYMBOL(sci_modify_parameter);

static void sci_free_parameter(struct sci_task_data *sci)
{
	struct sci_new_parameter *parameterlist = sci->parameterlist[0];
	struct sci_new_parameter *parameter;
	int i;

	for (i = 0; i < sci->parameterlist_len; i++) {
		parameter = parameterlist + i;
		if (parameter->new_page1) {
			if (parameter->new_page1->used_count > 1) {
				parameter->new_page1->used_count--;
			} else {
				free_page(parameter->new_page1->pfn_vaddr);
				kfree(parameter->new_page1);
			}
		}
		if (parameter->new_page2) {
			if (parameter->new_page2->used_count > 1) {
				parameter->new_page2->used_count--;
			} else {
				free_page(parameter->new_page2->pfn_vaddr);
				kfree(parameter->new_page2);
			}
		}
	}
}

static void sci_free_probe(struct sci_task_data *sci)
{
	struct sci_probe *probelist = sci->probelist[0];
	struct sci_probe *probe;
	int i;

	for (i = 0; i < sci->probelist_len; i++) {
		probe = probelist + i;
		if (probe) {
			if (probe->pfn_vaddr1)
				free_page(probe->pfn_vaddr1);
			if (probe->pfn_vaddr2)
				free_page(probe->pfn_vaddr2);
			if (probe->used_by_livepatch) {
				kfree(probe);
			}
		}
	}
}

inline void sci_sync_kernel(pgd_t *runtime_pgd, pgd_t *root_pgd)
{
	memcpy(runtime_pgd + KERNEL_PGD_BOUNDARY,
	       root_pgd + KERNEL_PGD_BOUNDARY, KERNEL_PGD_PTRS * sizeof(pgd_t));
}

static inline void sci_modify_pgtable(struct task_struct *tsk,
				      struct sci_task_data *sci)
{
	pgd_t *root_pgd;
	pgd_t *runtime_pgd;

	if (!static_cpu_has(X86_FEATURE_SCI))
		return;

	/*同步内核页表*/
	root_pgd = sci->mm->pgd;
	runtime_pgd = tsk->mm->pgd;

	sci_sync_kernel(runtime_pgd, root_pgd);

	//stack is in the VMALLOC
	sci_clone_vmalloc_as_pagefault(runtime_pgd);
}

// pfs design disable a sci-task to init another sci-task through syscall,
// since shared_pfs_sb in shared pv, which will be cover by sci pv
static void fill_sci_pfs(struct sci_task_data *sci)
{
	struct file_system_type *fs = get_fs_type(PFS_TYPE);
	struct super_block *shared_pfs_sb = NULL;

	hlist_for_each_entry (shared_pfs_sb, &fs->fs_supers, s_instances) {
		break;
	}
	if (!shared_pfs_sb)
		return;
	sci->shared_pfs_sb = shared_pfs_sb;
	sci->pfs_root_inode = shared_pfs_sb->s_root->d_inode;
}

static void private_vmalloc_init_percpu(struct sci_task_data *sci)
{
	unsigned long percpu_start;
	pte_t *target_pte;
	pgd_t *target_pgd;
	int i;

	sci->per_cpu_slot =
		kcalloc(PV_PER_CPU_SLOT_LEN, sizeof(pte_t *), GFP_KERNEL);
	if (!sci->per_cpu_slot) {
		pr_info("alloc per_cpu_slot failed\n");
		return;
	}

	i = 0;

	for (percpu_start = PV_PERCPU_START; percpu_start < PRIVATE_VMALLOC_END;
	     percpu_start += PAGE_SIZE) {
		pr_info("percpu_start: %lx, i = %d\n", percpu_start, i);
		target_pgd = pgd_offset_pgd(sci->mm->pgd, percpu_start);
		target_pte = sci_pagetable_walk_pte(sci->mm, target_pgd,
						    percpu_start);
		if (!target_pte) {
			pr_info("private_vmalloc_init_percpu error, target_pte NULL!\n");
			break;
		}

		if (i >= PV_PER_CPU_SLOT_LEN) {
			pr_info("per cpu slot overflow!\n");
			break;
		}
		sci->per_cpu_slot[i] = target_pte;
		i++;
	}
}

static void private_vmalloc_free_percpu(struct sci_task_data *sci)
{
	pgd_t *pgd, *pgdp;
	int i;

	pgdp = pgd = sci->mm->pgd;

	for (i = pgd_index(PV_PERCPU_START);
	     i <= pgd_index(PRIVATE_VMALLOC_END); i++) {
		pgd = pgdp + i;
		if (!pgd_none(*pgd))
			sci_free_p4d_range(sci->mm, pgd);
	}

	kfree(sci->per_cpu_slot);
}

static inline void init_private_vmalloc(struct sci_task_data *);
	
static void *pv_addr[PV_PREALLOCATE_SIZE];

static struct sci_task_data *sci_alloc(void)
{
	struct sci_task_data *sci;
	struct mm_struct *mm_new;
	int err = -ENOMEM;
	int i;

	if (!static_cpu_has(X86_FEATURE_SCI))
		return NULL;

	sci = kzalloc(sizeof(*sci), GFP_KERNEL);
	if (!sci)
		return NULL;

	mm_new = kzalloc(sizeof(*mm_new), GFP_KERNEL);
	if (!mm_new)
		return NULL;

	sci->mm = mm_new;

	sci->mm->pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);
	if (!sci->mm->pgd)
		goto free_ptes;

	sci->backtrace =
		kcalloc(SCI_MAX_BACKTRACE, sizeof(*sci->backtrace), GFP_KERNEL);
	if (!sci->backtrace)
		return NULL;

	sci->backtrace_size = 0;

	/*开始进行区域映射*/
	err = sci_pagetable_init(sci);
	if (err)
		goto free_ptes;

	// private vmalloc
	init_private_vmalloc(sci);

	fill_sci_pfs(sci);

	// reserved for private vfs, kernel stack, etc.
	root_private_vmalloc(PAGE_SIZE, sci);

	// reserved in pv area.
	for (i = 0; i < PV_PREALLOCATE_SIZE; i++)
		pv_addr[i] = root_private_vmalloc(PAGE_SIZE, sci);

	for (i = 0; i < PV_PREALLOCATE_SIZE; i++)
		root_private_vfree(sci, pv_addr[i]);


	private_vmalloc_init_percpu(sci);

	sci->probelist_len = 0;

	atomic_set(&sci->ref_count, 0);

	return sci;

	free_page((unsigned long)sci->mm->pgd);
free_ptes:
	kfree(sci);
	return NULL;
}

inline void sci_child_small_init(struct task_struct *tsk,
				 struct sci_task_data *sci)
{
	if (unlikely(!sci)) 
		return;

	tsk->sci = sci;
	tsk->in_isolated_syscall = 1;
	atomic_inc(&sci->ref_count);
}

//为子进程开启隔离，用参数sci作为同步内核页表的根
int __priviledged sci_child_init(struct task_struct *tsk, struct sci_task_data *sci)
{
	if (unlikely(!sci))
		return -1;

	sci_modify_pgtable(tsk, sci);
	tsk->sci = sci;
	tsk->in_isolated_syscall = 1;
	atomic_inc(&sci->ref_count);

	return 0;
}
EXPORT_SYMBOL(sci_child_init);

static void mutant_init_once(void);
//生成root sci,作为这个进程之后所有子进程的页表的模板
struct sci_task_data __priviledged *sci_init(void)
{
	struct sci_task_data *root;

	mutant_init_once();

	root = sci_alloc();
	if (!root)
		return NULL;

	root->probelist_len = 0;

	return root;
}
EXPORT_SYMBOL(sci_init);

void sci_child_exit(struct task_struct *tsk)
{
	struct sci_task_data *sci = tsk->sci;

	if (!static_cpu_has(X86_FEATURE_SCI) || !sci)
		return;

	tsk->in_isolated_syscall = 0;
	tsk->sci = NULL;
	atomic_dec(&sci->ref_count);
}

static inline void free_sci_private_vmalloc(struct sci_task_data *);

void __priviledged sci_exit(struct sci_task_data *sci)
{
	int ref_count;
	if (!static_cpu_has(X86_FEATURE_SCI) || !sci)
		return;

	ref_count = atomic_read(&sci->ref_count);
	if (ref_count)
		pr_info("sci: sci root left %d process!\n", ref_count);

	private_vmalloc_free_percpu(sci);

	free_sci_private_vmalloc(sci);
	sci->pv = NULL;
	kfree(sci->pv);

	kfree(sci->backtrace);

	sci_free_probe(sci);
	sci_free_parameter(sci);
	sci_free_pagetable(sci->mm, sci->mm->pgd);
	free_page((unsigned long)sci->mm->pgd);
	kfree(sci->mm);
	sci->mm = NULL;
	kfree(sci);
	sci = NULL;
}
EXPORT_SYMBOL(sci_exit);

/*
*sci函数修改测试用样例函数
*/
void sci_function_modify_example(int a, int b)
{
	int c;
	c = a + b;
	pr_info("sci: this is original function(sci_function_modify_example), %d + %d = %d\n",
	       a, b, c);
}
EXPORT_SYMBOL(sci_function_modify_example);

static void sci_add_rip(struct sci_task_data *sci, unsigned long rip)
{
	int i;

	for (i = sci->backtrace_size - 1; i >= 0; i--)
		if (rip == sci->backtrace[i])
			return;

	sci->backtrace[sci->backtrace_size++] = rip;
}

//check kernel code text access
static int sci_verify_code_access(struct sci_task_data *sci,
				  struct pt_regs *regs, unsigned long addr)
{
	char namebuf[KSYM_NAME_LEN];
	unsigned long offset, size;
	const char *symbol;
	char *modname;

	/* instruction fetch outside kernel or module text */
	if (!(is_kernel_text(addr) || is_module_text_address(addr))) 
		return 0;
	
	if (addr >= (u64)__priviledged_text_start && addr <= (u64)__priviledged_text_end)
		return 0;

	/* no symbol matches the address */
	symbol = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);
	if (!symbol)
		return 0;

	/* BPF or ftrace? */
	if (symbol != namebuf)
		return 0;

	sci_add_rip(sci, regs->ip);

	return 1;
}

bool sci_verify_and_map(struct pt_regs *regs, unsigned long addr,
			unsigned long hw_error_code)
{
	struct task_struct *tsk = current;
	struct sci_task_data *sci = tsk->sci;
	pte_t *pte;

	/* run out of room for metadata, can't grant access */
	if (sci->backtrace_size >= SCI_MAX_BACKTRACE)
		return false;

	/* only code access is checked */
	if ((hw_error_code & X86_PF_INSTR) &&
	    !sci_verify_code_access(sci, regs, addr))
		return false;

	pte = sci_clone_page_for_pagefault(sci->mm, root_mm->pgd, tsk->mm->pgd,
					   addr);

	return !!pte;
}

void __init sci_check_boottime_disable(void)
{
	char arg[5];
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_PCID)) {
		pr_info("System call isolation requires PCID\n");
		return;
	}

	/* Assume SCI is disabled unless explicitly overridden. */
	ret = cmdline_find_option(boot_command_line, "sci", arg, sizeof(arg));
	if (ret == 2 && !strncmp(arg, "on", 2)) {
		setup_force_cpu_cap(X86_FEATURE_SCI);
		pr_info("System call isolation is enabled\n");
	} else
		pr_info("System call isolation is disabled\n");
}

//static noinline int sci_iso_rw_page(struct sci_task_data *sci,
//				 sci_rw_param_page *p)
//	__attribute__((optimize("O0")));
static inline int sci_iso_rw_page(struct sci_task_data *sci,
				  sci_rw_param_page *p)
{
	unsigned long orig_page_addr = (unsigned long)_text + p->page_offset;
	unsigned long iso_page_addr;
	unsigned i;

	iso_page_addr = sci_map_new_page(sci, PAGE_KERNEL_EXEC, orig_page_addr);
	if (!iso_page_addr)
		return -ENOMEM;

	memcpy((void *)iso_page_addr, (void *)(orig_page_addr & PAGE_MASK),
	       PAGE_SIZE);
	for (i = 0; i < p->sci_rw_params_num; i++) {
		unsigned offset = p->sci_rw_params[i].offset +
				  p->sci_rw_params[i].invalid_bytes_num;
		unsigned len = 8 - p->sci_rw_params[i].invalid_bytes_num;
		memcpy((void *)(iso_page_addr + offset),
		       (void *)(orig_page_addr + offset), len);
	}

	return 0;
}

int __priviledged sci_iso_rw_param(struct sci_task_data *sci,
		     sci_rw_param_page **sci_rw_param_pages,
		     unsigned sci_rw_param_page_num)
{
	unsigned i;
	for (i = 0; i < sci_rw_param_page_num; i++) {
		int ret = sci_iso_rw_page(sci, sci_rw_param_pages[i]);
		if (ret)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(sci_iso_rw_param);

extern void private_vmalloc_init_free_space(struct sci_private_vmalloc *);
extern void private_vmalloc_cache_init(struct sci_private_vmalloc *);
static inline void init_private_vmalloc(struct sci_task_data *sci)
{
	struct sci_private_vmalloc *pv =
		kzalloc(sizeof(struct sci_private_vmalloc), GFP_KERNEL);
	sci->pv = pv;

	pv->vmap_area_root = RB_ROOT;
	INIT_LIST_HEAD(&pv->vmap_area_list);

	pv->free_vmap_area_root = RB_ROOT;
	INIT_LIST_HEAD(&pv->free_vmap_area_list);
	private_vmalloc_init_free_space(pv);

	spin_lock_init(&pv->vmap_area_lock);

	private_vmalloc_cache_init(pv);
}

extern void pv_va_free(struct sci_task_data *);
extern void pv_vpl_free(struct sci_private_vmalloc *);
extern void pv_fv_free(struct sci_private_vmalloc *);
extern void pv_used_pages_free(struct sci_private_vmalloc *);
extern void pv_unused_pages_free(struct sci_task_data *);

static inline void free_sci_private_vmalloc(struct sci_task_data *sci)
{
	pv_va_free(sci);
	pv_vpl_free(sci->pv);
	pv_fv_free(sci->pv);
	pv_used_pages_free(sci->pv);
	pv_unused_pages_free(sci);
}

struct walk_pgtable_entry {
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long cur, end;
};

static struct walk_pgtable_entry *
init_walk_pgtable_entry(pgd_t *pgd, unsigned long start, unsigned long end)
{
#define init_mid_level_entry_template(upper_level, lower_level, error_tag)     \
	{                                                                      \
		entry->lower_level =                                           \
			lower_level##_offset(entry->upper_level, start);       \
		if (!entry->lower_level) {                                     \
			goto error_tag;                                        \
		}                                                              \
	}

	struct walk_pgtable_entry *entry =
		kzalloc(sizeof(struct walk_pgtable_entry), GFP_KERNEL);
	entry->pgd = pgd_offset_pgd(pgd, start);
	init_mid_level_entry_template(pgd, p4d, error);
	init_mid_level_entry_template(p4d, pud, error);
	init_mid_level_entry_template(pud, pmd, error);

	entry->pte = pte_offset_kernel(entry->pmd, start);
	entry->cur = start;
	entry->end = end;

	return entry;

error:
	kfree(entry);
	return NULL;
#undef init_mid_level_entry
}

static inline void next_pgd(struct walk_pgtable_entry *entry)
{
	unsigned long next = pgd_addr_end(entry->cur, entry->end);
	if (next >= entry->end) {
		entry->pgd = NULL;
		return;
	}
	if (entry->cur & PGDIR_MASK)
		return;
	entry->pgd++;
}

#define next_entry_template(upper_level, lower_level, upper_level_page_mask)   \
	{                                                                      \
		unsigned long next =                                           \
			lower_level##_addr_end(entry->cur, entry->end);        \
		if (next >= entry->end) {                                      \
			entry->lower_level = NULL;                             \
			return;                                                \
		}                                                              \
		if (!(entry->cur & upper_level_page_mask)) {                   \
			next_##upper_level(entry);                             \
		}                                                              \
		entry->lower_level =                                           \
			entry->upper_level ?                                   \
				lower_level##_offset(entry->upper_level,       \
						     entry->cur) :             \
				NULL;                                          \
	}

static inline void next_p4d(struct walk_pgtable_entry *entry)
{
	next_entry_template(pgd, p4d, PGDIR_MASK)
}
static inline void next_pud(struct walk_pgtable_entry *entry)
{
	next_entry_template(p4d, pud, P4D_MASK)
}
static inline void next_pmd(struct walk_pgtable_entry *entry)
{
	next_entry_template(pud, pmd, PUD_MASK)
}

#undef next_entry_template

static inline void next_pte(struct walk_pgtable_entry *entry)
{
	entry->cur += PAGE_SIZE;
	if (entry->cur >= entry->end) {
		entry->pte = NULL;
		return;
	}
	if (!(entry->cur & PMD_MASK))
		next_pmd(entry);
	entry->pte =
		entry->pmd ? pte_offset_kernel(entry->pmd, entry->cur) : NULL;
}

static void free_walk_pgtable_entry(struct walk_pgtable_entry *entry)
{
	kfree(entry);
}

static inline int pte_accessed(pte_t pte)
{
	return pte_flags(pte) & _PAGE_ACCESSED;
}

static int default_debloat(pte_t *pte, void *debloat_argv)
{
	if (pte_accessed(*pte))
		return 0;

	*pte = pte_clear_flags(*pte, _PAGE_ACCESSED);
	return 0;
}

int __priviledged sci_debloat_kernel(void *debloat_argv)
{
	int ret = 0;
	struct walk_pgtable_entry *entry;
	unsigned long text_size = 0, debloat_size = 0;
	if (!current->sci)
		return -EPERM;

	entry = init_walk_pgtable_entry(current->sci->mm->pgd,
					(unsigned long)_text,
					(unsigned long)_etext);
	while (entry->pte) {
		text_size++;
		if (!pte_accessed(*entry->pte))
			debloat_size++;

		if (!current->sci->debloat)
			ret = default_debloat(entry->pte, NULL);
		else
			ret = current->sci->debloat(entry->pte, debloat_argv);

		if (ret)
			goto free_entry;
		next_pte(entry);
	}


free_entry:
	free_walk_pgtable_entry(entry);
	entry = NULL;

	return ret;
}

// unmap a pmd area in sci_isolated_rootmm direct memory map region
void mutant_unmap_dmm_pmd(unsigned long pmd_va)
{
	struct walk_pgtable_entry *entry = init_walk_pgtable_entry(
		mutant_rootmm->pgd, pmd_va, pmd_va + PMD_SIZE);
		
	struct walk_pgtable_entry *entry_root = init_walk_pgtable_entry(
		root_mm->pgd, pmd_va, pmd_va + PMD_SIZE);
			
	pmd_t pmd = native_make_pmd(_PAGE_PSE);
	pmd_t pmd_root = pmd_clear_flags(*(entry_root->pmd), _PAGE_GLOBAL);
	
	set_pmd(entry->pmd, pmd);
	
	pr_info("mutant_unmap_dmm_pmd, root pmd before: %lx\n", entry_root->pmd->pmd);
	
	set_pmd(entry_root->pmd, pmd_root);
	
	pr_info("mutant_unmap_dmm_pmd, root pmd after: %lx\n", entry_root->pmd->pmd);
	
	flush_tlb_kernel_range(pmd_va, pmd_va + PMD_SIZE);

	free_walk_pgtable_entry(entry);
	
	free_walk_pgtable_entry(entry_root);
}
EXPORT_SYMBOL(mutant_unmap_dmm_pmd);

// set a pmd in kernel priviledged text as non-global
#ifdef PAGE_TABLE_ISOLATION
void __priviledged mutant_set_priviledge_ngbl(void)
{	
	return;
}
#else
void __priviledged mutant_set_priviledge_ngbl(void)
{
	struct walk_pgtable_entry *entry = init_walk_pgtable_entry(
		root_mm->pgd, (u64)__priviledged_text_start, (u64)__priviledged_text_start + PMD_SIZE);
		
	pmd_t pmd = pmd_clear_flags(*(entry->pmd), _PAGE_GLOBAL);
	
	set_pmd(entry->pmd, pmd);
	
	pr_info("mutant_set_priviledge_ngbl, root pmd before: %lx\n", entry->pmd->pmd);
	
	set_pmd(entry->pmd, pmd);
	
	pr_info("mutant_set_priviledge_ngbl, root pmd after: %lx\n", entry->pmd->pmd);
	
	free_walk_pgtable_entry(entry);
}
#endif

void mutant_unmap_pmd_woflush(unsigned long pmd_va)
{
	struct walk_pgtable_entry *entry = init_walk_pgtable_entry(
		mutant_rootmm->pgd, pmd_va, pmd_va + PMD_SIZE);
	pmd_t pmd = native_make_pmd(_PAGE_PSE);

	set_pmd(entry->pmd, pmd);

	free_walk_pgtable_entry(entry);
}

void mutant_flush_tlb(unsigned long pmd_va)
{
	flush_tlb_kernel_range(pmd_va, pmd_va + PMD_SIZE);
}

struct sci_task_data *test_root;

static int sci_init_user_interface(struct task_struct *tsk)
{
	if (!tsk)
		return 0;

	test_root = sci_init();
	if (!test_root)
		return 0;

	sci_child_init(tsk, test_root);

	return 0;
}

static int sci_exit_user_interface(struct sci_task_data *sci_root)
{
	if (!sci_root)
		return 0;

	sci_exit(sci_root);

	return 1;
}

struct sci_task_data *mutant_templates[MAX_MUTANT_TEMPLATE_NUM];
struct dentry *mutant_templates_dentry[MAX_MUTANT_TEMPLATE_NUM];

static struct dentry *pgtable_debug_root;

static int ptdump_curtemplate_show(struct seq_file *m, void *v)
{
	int id;

	if (pgtable_debug_root){
		sscanf(m->file->f_path.dentry->d_iname, "%d", &id);
		pr_info("%s, grep template number %d\n", __func__, id);
		ptdump_walk_pgd_level_debugfs(m, mutant_templates[id]->mm->pgd, false);
	}
	
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ptdump_curtemplate);

static int init_one_mutant_template(void)
{
	int i;
	char str[5];
	for (i = 0; i < MAX_MUTANT_TEMPLATE_NUM; i++) {
		if (mutant_templates[i])
			continue;
		mutant_templates[i] = sci_init();
		
		if (!pgtable_debug_root) {
			pgtable_debug_root = debugfs_lookup("page_tables", NULL);
		}
		
		if (pgtable_debug_root) {
			sprintf(str, "%d", i);
			mutant_templates_dentry[i] = debugfs_create_file(str, 0400,
					pgtable_debug_root, NULL, &ptdump_curtemplate_fops);
		}
		break;
	}

	return i > MAX_MUTANT_TEMPLATE_NUM ? -1 : i;
}

#define test_pages_num 32
#define test_background_round 1000
#define test_round 100

static void sci_pv_test_background(void)
{
	void *addr[test_pages_num];
	int i, background_round;

	for (background_round = 0; background_round < test_background_round;
	     background_round++) {
		for (i = 0; i < test_pages_num; i++) {
			addr[i] = private_vmalloc(PAGE_SIZE);
			usleep_range(64, 128);
		}

		for (i = 0; i < test_pages_num; i++) {
			private_vfree(addr[i]);
			usleep_range(64, 128);
		}
	}
}

static void sci_pv_test(void)
{
	void *addr[test_pages_num];
	unsigned long long time, times[test_pages_num];
	int i, round;

	for (round = 0; round < test_round; round++) {
		for (i = 0; i < test_pages_num; i++) {
			time = rdtsc();
			addr[i] = private_vmalloc(PAGE_SIZE);
			times[i] = rdtsc() - time;
			usleep_range(64, 128);
		}

		for (i = 0; i < test_pages_num; i++) {
			pr_info("Mutant pv test: pid %d private vmalloc time %llu\n",
			       current->pid, times[i]);
			private_vfree(addr[i]);
		}
	}
}

static void sci_vm_test(void)
{
	void *addr[test_pages_num];
	unsigned long long time, times[test_pages_num];
	int i;

	for (i = 0; i < test_pages_num; i++) {
		time = rdtsc();
		addr[i] = vzalloc(PAGE_SIZE);
		times[i] = rdtsc() - time;
		usleep_range(64, 128);
	}

	for (i = 0; i < test_pages_num; i++) {
		pr_info("Mutant pv test: pid %d vmalloc time %llu\n",
		       current->pid, times[i]);
		vfree(addr[i]);
	}
}

static void sci_km_test(void)
{
	void *addr[test_pages_num];
	unsigned long long time, times[test_pages_num];
	int i;

	for (i = 0; i < test_pages_num; i++) {
		time = rdtsc();
		addr[i] = kmalloc(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
		times[i] = rdtsc() - time;
		usleep_range(64, 128);
	}

	for (i = 0; i < test_pages_num; i++) {
		pr_info("Mutant pv test: pid %d kmalloc time %llu\n",
		       current->pid, times[i]);
		kfree(addr[i]);
	}
}

static void mutant_pvp_test(void)
{
	struct page *pages[test_pages_num];
	unsigned long long time, times[test_pages_num];
	int i, round;

	for (round = 0; round < test_round; round++) {
		for (i = 0; i < test_pages_num; i++) {
			time = rdtsc();
			pages[i] = get_pvp_cache_page();
			times[i] = rdtsc() - time;
			usleep_range(64, 128);
		}

		for (i = 0; i < test_pages_num; i++) {
			pr_info("Mutant pv test: pid %d pvp time %llu\n",
			       current->pid, times[i]);
			put_pvp_cache_page(pages[i]);
		}
	}
}

static void mutant_pvp_test_background(void)
{
	struct page *pages[test_pages_num];
	int i, background_round;

	for (background_round = 0; background_round < test_background_round;
	     background_round++) {
		for (i = 0; i < test_pages_num; i++) {
			pages[i] = get_pvp_cache_page();
			usleep_range(64, 128);
		}

		for (i = 0; i < test_pages_num; i++) {
			put_pvp_cache_page(pages[i]);
			usleep_range(64, 128);
		}
	}
}

#undef test_pages_num
#undef test_background_round
#undef test_round

#define SCI_CMD_DEBLOAT_KERNEL 2
#define SCI_CMD_PFS 3
#define SCI_EXIT 4
#define SCI_TEST_PV 100
#define SCI_TEST_VM 101
#define SCI_TEST_KM 102
#define SCI_TEST_PV_BACKGROUND 103
#define SCI_TEST_SWAP 104
#define MUTANT_TEMPLATE_INIT 105
#define MUTANT_TEST_PVP 106
#define MUTANT_TEST_PVP_BACKGROUND 107

extern struct dentry *private_pfs_d_make_root(struct super_block *,
					      struct inode *);
extern unsigned long shrink_anon_pvp_pages_task(unsigned long, unsigned long);
int ksys_sci_ctl(unsigned cmd)
{
	int ret = 0;
	switch (cmd) {
	default:
		// try to mutant init
		struct task_struct *child_task =
			pid_task(find_vpid(cmd), PIDTYPE_PID);
		ret = sci_init_user_interface(child_task);
		break;
	case SCI_EXIT:
		sci_exit_user_interface(test_root);
		break;
	case SCI_CMD_DEBLOAT_KERNEL:
		ret = sci_debloat_kernel(NULL);
		break;
	case SCI_CMD_PFS:
		if (!private_pfs_d_make_root(current->sci->shared_pfs_sb,
					     current->sci->pfs_root_inode))
			ret = -1;
		break;
	case SCI_TEST_PV:
		sci_pv_test();
		break;
	case SCI_TEST_PV_BACKGROUND:
		sci_pv_test_background();
		break;
	case SCI_TEST_VM:
		sci_vm_test();
		break;
	case SCI_TEST_KM:
		sci_km_test();
		break;
	case SCI_TEST_SWAP:
		shrink_anon_pvp_pages_task(0, 1);
		msleep(1000);
		shrink_anon_pvp_pages_task(1, 1);
		break;
	case MUTANT_TEMPLATE_INIT:
		ret = init_one_mutant_template();
		break;
	case MUTANT_TEST_PVP:
		mutant_pvp_test();
		break;
	case MUTANT_TEST_PVP_BACKGROUND:
		mutant_pvp_test_background();
		break;
	}

	return ret;
}

SYSCALL_DEFINE1(sci_ctl, unsigned, cmd)
{
	return ksys_sci_ctl(cmd);
}

#define TLB_TEST_OUTER_ROUND 4
#define magic_number 2023

static inline void _flush_one_tlb(unsigned long addr)
{
	asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
}

int mutant_tlb_test(unsigned long start_addr, int test_round){
	uint64_t start, end, time;
	unsigned long addr;
	int i, ret, k, m, n;
	
	time = 0;
	for(k = 0; k < TLB_TEST_OUTER_ROUND; k++){
		for(i = 0; i < test_round * 2; i++){
			if (i % 2 == 0){
				addr = start_addr + i * PAGE_SIZE;
				for (m = 0; m < 100; m++){
					n++;
				}
				//_flush_one_tlb(addr);
				start = rdtsc();
				*(int *)addr = magic_number;
				end = rdtsc();
			
				pr_info("addr: %lx; %llu\n", addr, (end - start));
				time += (end - start);
			}else{
				ssleep(0.2);
			}
		}
		ssleep(2);
	}
	time = time / (test_round * TLB_TEST_OUTER_ROUND);
	pr_info("write access average time: %llu\n", time);
	
	time = 0;
	for(k = 0; k < TLB_TEST_OUTER_ROUND; k++){
		for(i = 0; i < test_round * 2; i++){
			if (i % 2 == 0){
				addr = start_addr + i * PAGE_SIZE;
				for (m = 0; m < 100; m++){
					n++;
				}
				//_flush_one_tlb(addr);
				start = rdtsc();
				ret = *(int *)addr;
				end = rdtsc();
				if (ret != magic_number){
					pr_info("read address access failed! addr: %lx, content: %d, should be: %d\n", addr, ret, magic_number);
					break;
				}
				pr_info("addr: %lx; %llu\n", addr, (end - start));
				time += (end - start);
			}else{
				ssleep(0.2);
			}
		}
		ssleep(2);
	}
	time = time / (test_round * TLB_TEST_OUTER_ROUND);
	pr_info("read access average time: %llu\n", time);
	
	return ret;
}

#define MUTANT_TEST_ACCESS_ADDR 1
#define MUTANT_TEST_READ_ADDR 2
#define MUTANT_TEST_TLB 3
int ksys_mutant_ctl2(unsigned cmd, unsigned long argv, int content)
{
	int ret = 0;
	switch (cmd) {
	default:
		ret = -1;
		break;
	case MUTANT_TEST_ACCESS_ADDR:
		*(int *)argv = content;
		ret = 0;
		break;
	case MUTANT_TEST_READ_ADDR:
		ret = *(int *)argv;
		break;
	case MUTANT_TEST_TLB:
		ssleep(5);
		mutant_tlb_test(argv, content);
		break;
	}

	return ret;
}

SYSCALL_DEFINE3(mutant_ctl2, unsigned, cmd, unsigned long, argv, int, content)
{
	return ksys_mutant_ctl2(cmd, argv, content);
}

/*
 * mutant_pXX_alloc() functions are equivalent to kernel pXX_alloc() functions
 * but, in addition, they keep track of new pages allocated.
 */
#define mutant_pXX_alloc(pxx, upper_pxx)                                       \
	{                                                                      \
		struct page *page;                                             \
		pxx##_t *pxx;                                                  \
                                                                               \
		if (upper_pxx##_none(*upper_pxx)) {                            \
			page = alloc_page(GFP_KERNEL | __GFP_ZERO);            \
			if (!page)                                             \
				return ERR_PTR(-ENOMEM);                       \
			pxx = (pxx##_t *)page_address(page);                   \
			set_##upper_pxx##_safe(upper_pxx,                      \
					       __##upper_pxx(__pa(pxx) |       \
							     _KERNPG_TABLE));  \
			pxx = pxx##_offset(upper_pxx, addr);                   \
		} else                                                         \
			pxx = pxx##_offset(upper_pxx, addr);                   \
                                                                               \
		return pxx;                                                    \
	}

#define pte_offset pte_offset_map

static pte_t *mutant_pte_alloc(pmd_t *pmd, unsigned long addr)
{
	mutant_pXX_alloc(pte, pmd)
}

#undef pte_offset

static pmd_t *mutant_pmd_alloc(pud_t *pud, unsigned long addr)
{
	mutant_pXX_alloc(pmd, pud)
}

static pud_t *mutant_pud_alloc(p4d_t *p4d, unsigned long addr)
{
	mutant_pXX_alloc(pud, p4d)
}

static p4d_t *mutant_p4d_alloc(pgd_t *pgd, unsigned long addr)
{
	if (!pgtable_l5_enabled())
		return (p4d_t *)pgd;

	mutant_pXX_alloc(p4d, pgd)
}

#undef mutant_pXX_alloc

/*
 * mutant_set_pXX() functions are equivalent to kernel set_pXX() functions
 * but, in addition, they ensure that they are not overwriting an already
 * existing reference in the page table. Otherwise an error is returned.
 */
/*
static int mutant_set_pte(pte_t *pte, pte_t pte_value)
{
	set_pte(pte, pte_value);

	return 0;
}
*/
#define mutant_set_pXX(pxx, pxx_value)                                         \
	{                                                                      \
		if (pxx##_val(*pxx) == pxx##_val(pxx_value))                   \
			return 0;                                              \
		if (!pxx##_none(*pxx))                                         \
			return -EBUSY;                                         \
		set_##pxx(pxx, pxx_value);                                     \
		return 0;                                                      \
	}

static int mutant_set_pmd(pmd_t *pmd, pmd_t pmd_value)
{
	mutant_set_pXX(pmd, pmd_value)
}

static int mutant_set_pud(pud_t *pud, pud_t pud_value)
{
	mutant_set_pXX(pud, pud_value)
}

static int mutant_set_p4d(p4d_t *p4d, p4d_t p4d_value)
{
	mutant_set_pXX(p4d, p4d_value)
}

static int mutant_set_pgd(pgd_t *pgd, pgd_t pgd_value)
{
	mutant_set_pXX(pgd, pgd_value)
}

#undef mutant_set_pXX
/*
static int mutant_copy_pte_range(pmd_t *dst_pmd, pmd_t *src_pmd,
				 unsigned long addr, unsigned long end)
{
	pte_t *src_pte, *dst_pte;

	dst_pte = mutant_pte_alloc(dst_pmd, addr);
	if (IS_ERR(dst_pte))
		return PTR_ERR(dst_pte);

	addr &= PAGE_MASK;
	src_pte = pte_offset_map(src_pmd, addr);

	do {
		mutant_set_pte(dst_pte, *src_pte);
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr < end);

	return 0;
}
*/
#define mutant_copy_pXX_range(lower_pxx, pxx, upper_pxx)                       \
	{                                                                      \
		pxx##_t *src, *dst;                                            \
		unsigned long next;                                            \
		int err;                                                       \
                                                                               \
		dst = mutant_##pxx##_alloc(dst_##upper_pxx, addr);             \
		if (IS_ERR(dst))                                               \
			return PTR_ERR(dst);                                   \
                                                                               \
		src = pxx##_offset(src_##upper_pxx, addr);                     \
                                                                               \
		do {                                                           \
			next = pxx##_addr_end(addr, end);                      \
			if (mutant_##pxx##_none(src)) {                        \
				err = mutant_set_##pxx(dst, *src);             \
				if (err)                                       \
					return err;                            \
				continue;                                      \
			}                                                      \
                                                                               \
			if (!mutant_##pxx##_present(src))                      \
				continue;                                      \
                                                                               \
			err = mutant_copy_##lower_pxx##_range(dst, src, addr,  \
							      next);           \
			if (err)                                               \
				return err;                                    \
		} while (dst++, src++, addr = next, addr < end);               \
                                                                               \
		return 0;                                                      \
	}

#define mutant_pmd_none(pmdp)                                                  \
	(pmd_none(*pmdp) || pmd_trans_huge(*pmdp) || pmd_devmap(*pmdp))
#define mutant_pmd_present(pmdp) (pmd_present(*pmdp))

static int mutant_copy_pmd_range(pud_t *dst_pud, pud_t *src_pud,
				 unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;

	dst_pmd = mutant_pmd_alloc(dst_pud, addr);
	if (IS_ERR(dst_pmd))
		return PTR_ERR(dst_pmd);

	addr &= PAGE_MASK;
	src_pmd = pmd_offset(src_pud, addr);

	do {
		mutant_set_pmd(dst_pmd, *src_pmd);
		if (!pmd_write(*dst_pmd))
			pr_info("mroot set pmd without RW, addr: %lx\n", addr);
	} while (dst_pmd++, src_pmd++, addr += PMD_PAGE_SIZE, addr < end);

	return 0;
}

#undef mutant_pmd_none
#undef mutant_pmd_present

#define mutant_pud_none(pudp)                                                  \
	(pud_none(*pudp) || pud_trans_huge(*pudp) || pud_devmap(*pudp))
#define mutant_pud_present(pudp) (1)

static int mutant_copy_pud_range(p4d_t *dst_p4d, p4d_t *src_p4d,
				 unsigned long addr, unsigned long end)
{
	mutant_copy_pXX_range(pmd, pud, p4d)
}

#undef mutant_pud_none
#undef mutant_pud_present

#define mutant_p4d_none(p4dp) p4d_none(*p4dp)
#define mutant_p4d_present(p4dp) (1)

static int mutant_copy_p4d_range(pgd_t *dst_pgd, pgd_t *src_pgd,
				 unsigned long addr, unsigned long end)
{
	mutant_copy_pXX_range(pud, p4d, pgd)
}

#undef mutant_p4d_none
#undef mutant_p4d_present

#undef mutant_copy_pXX_range

static int mutant_copy_pgd_range(unsigned long addr, unsigned long end)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	int err;

	dst_pgd = pgd_offset_pgd(mutant_rootmm->pgd, addr);
	src_pgd = pgd_offset_pgd(root_mm->pgd, addr);

	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*src_pgd)) {
			err = mutant_set_pgd(dst_pgd, *src_pgd);
			if (err)
				return err;
			continue;
		}

		err = mutant_copy_p4d_range(dst_pgd, src_pgd, addr, next);
		if (err)
			return err;
	} while (dst_pgd++, src_pgd++, addr = next, addr < end);

	return 0;
}

/*
* Copy page table entries from the current page table (i.e. from the
 * kernel page table) to the specified page-table. The level
 * parameter specifies the page-table level (PGD, P4D, PUD PMD, PTE)
 * at which the copy should be done.
 */
static inline int mutant_map_range(unsigned long start, unsigned long end)
{
	return mutant_copy_pgd_range(start, end);
}

static void mutant_rootmm_init(void)
{
	int err;

	if (mutant_rootmm)
		return;

	mutant_rootmm = kzalloc(sizeof(*mutant_rootmm), GFP_KERNEL);
	if (!mutant_rootmm)
		return;

	mutant_rootmm->pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);

	if (!mutant_rootmm->pgd)
		return;

	if (pgtable_l5_enabled())
		err = mutant_map_range(0xff11000000000000, 0xff90ffffffffffff);
	else
		err = mutant_map_range(0xffff888000000000, 0xffffc87fffffffff);

	if (err)
		pr_err("mutant_rootmm_init failed!\n");
	else
		pr_info("make mutant_rootmm pgd in level %d pagetable success.\n",
			pgtable_l5_enabled() ? 5 : 4);
}

static DEFINE_SPINLOCK(mutant_init_lock);
static void mutant_init_once(void)
{
	static int mutant_inited = 0;

	if (likely(mutant_inited))
		return;

	spin_lock(&mutant_init_lock);
	if (mutant_inited) {
		spin_unlock(&mutant_init_lock);
		return;
	}

	mutant_inited = 1;
	spin_unlock(&mutant_init_lock);

	mutant_rootmm_init();//build rootmm
	
	mutant_set_priviledge_ngbl();//set priviledge-text as non-global

	if (!PV_PERCPU_START) {
		PV_PERCPU_START = (PRIVATE_VMALLOC_END + 1 -
				   (num_processors)*2 * PAGE_SIZE);
		PV_PER_CPU_SLOT_LEN = num_processors * 2;
		pr_info("sci boot, PV_PERCPU_START: %lx, PV_PER_CPU_SLOT_LEN: %lx\n",
		       PV_PERCPU_START, PV_PER_CPU_SLOT_LEN);
	}
}

SYSCALL_DEFINE1(mutant_exit_template, unsigned, template_id)
{
	int ret;
	ret = sci_exit_user_interface(mutant_templates[template_id]);
	if (ret) {
		mutant_templates[template_id] = NULL;

		if (mutant_templates_dentry[template_id]) {
			debugfs_remove(mutant_templates_dentry[template_id]);
			mutant_templates_dentry[template_id] = NULL;
		}

	}
	return ret;
}

SYSCALL_DEFINE1(mutant_fork, unsigned, template_id)
{
	long pid;
#ifdef CONFIG_MMU
	struct kernel_clone_args args = {
		.exit_signal = SIGCHLD,
	};

	if (!mutant_templates[template_id])
		return -EINVAL;

	pid = _mutant_do_fork(&args, template_id);

	return pid;

#else
	/* can not support in nommu mode */
	return -EINVAL;
#endif
}
