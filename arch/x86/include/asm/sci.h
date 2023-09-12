// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_SCI_H
#define _ASM_X86_SCI_H

#include "linux/llist.h"
#include "linux/mutex.h"
#include "linux/rbtree.h"
#include "linux/spinlock_types.h"
#include "linux/types.h"
#include "linux/workqueue.h"
#define SCI_MAX_PTES 512
#define SCI_MAX_BACKTRACE 512
#define SCI_MAX_PROBLIST 4
#define SCI_MAX_PARAMETERLIST 4
#define SCI_MAX_PARAM_PER_PAGE 64
#define MAX_MUTANT_TEMPLATE_NUM 32
#define PV_PREALLOCATE_SIZE 512

typedef struct sci_rw_param {
	unsigned long target_addr;
	unsigned offset;
	unsigned invalid_bytes_num;
} sci_rw_param;

typedef struct sci_rw_param_page {
	unsigned long page_offset;
	sci_rw_param *sci_rw_params;
	unsigned sci_rw_params_num;
} sci_rw_param_page;

/* used for sci_new_parameter and sci_probe*/
struct sci_probe_page {
	unsigned long pfn_vaddr;
	int used_count;
};

/*sci read only parameter custom */
struct sci_new_parameter {
	const char *name;
	void *orig_addr;

	//the first page used
	unsigned long pg_vaddr1;
	struct sci_probe_page *new_page1;

	//the second page used
	unsigned long pg_vaddr2;
	struct sci_probe_page *new_page2;

	void *content;
	unsigned long origin_para_size;
};

struct sci_probe {
	/*符号名称*/
	const char *name;
	/*新函数的地址*/
	void *new_func;
	/*符号原地址*/
	void *orig_func;
	/*桩函数地址*/
	void *stub_func;

	char save_ip[15];
	char jump_ip[15];
	int save_len;

	/*新分配页的物理地址与虚拟地址*/
	unsigned long pfn_vaddr1;
	unsigned long pfn_vaddr2;

	/**/
	bool used_by_livepatch;
};

struct sci_private_vmalloc {
	struct rb_root vmap_area_root;
	struct list_head vmap_area_list;
	struct rb_root free_vmap_area_root;
	struct list_head free_vmap_area_list;
	struct llist_head vmap_purge_list;
	atomic_long_t nr_vmalloc_pages;
	atomic_long_t vmap_lazy_nr;
	spinlock_t vmap_area_lock;
	struct mutex vmap_purge_lock;

	struct list_head pv_cache_list;
	spinlock_t pv_cache_lock;
	struct list_head used_pv_page_list;
	spinlock_t used_pv_page_list_lock;
};

typedef int debloat_func(pte_t *pte, void *user_argv);

struct sci_task_data {
	struct task_struct *pivot_task; //init task in the ns
	// mm->pgd as a template, it will not be loaded into CR3.
	struct mm_struct *mm;
	struct sci_private_vmalloc *pv;
	debloat_func *debloat;

	struct sci_probe *probelist[SCI_MAX_PROBLIST];
	int probelist_len;
	struct sci_new_parameter *parameterlist[SCI_MAX_PARAMETERLIST];
	int parameterlist_len;

	unsigned long backtrace_size;
	unsigned long *backtrace;

	// shared super block / root inode for private vfs
	struct super_block *shared_pfs_sb;
	struct inode *pfs_root_inode;

	pte_t **per_cpu_slot;

	atomic_t ref_count;
};

struct sci_percpu_data {
	unsigned long sci_syscall;
};

extern char __priviledged_text_start[], __priviledged_text_end[];

#define __priviledged __section(.priviledged.text)


#ifdef CONFIG_SYSCALL_ISOLATION

extern struct page *global_zero_page;

extern unsigned long PV_PERCPU_START;

extern unsigned mutant_debug_level;

#define MUTANT_EMERG 1
#define MUTANT_ERR (1 << 2)
#define MUTANT_WARNING (1 << 3)
#define MUTANT_INFO (1 << 4)
#define MUTANT_DEBUG (1 << 5)
#define MUTANT_COW_clear_time (1 << 6)
#define MUTANT_switch_time (1 << 7)

#define mutant_printk(msg_level, fmt, args...)                                 \
	{                                                                      \
		if (msg_level & mutant_debug_level) {                          \
			printk(KERN_CONT "Mutant: ");                          \
			printk(fmt, ##args);                                   \
		}                                                              \
	}

#define SCI_NEW_PARAMETER(_name, _content)                                     \
	{                                                                      \
		.name = (_name), .content = (_content),                        \
	}

#define SCI_PORBE(_name, _function)                                            \
	{                                                                      \
		.name = (_name), .new_func = (_function),                      \
	}

#define PFS_DEFAULT_PATH "/.private-ramfs"
#define PFS_TYPE "private-ramfs"
#define PFS_DENTRY_POS (PRIVATE_VMALLOC_START)

extern struct list_head anon_pvp_page_list;

extern struct sci_task_data *mutant_templates[MAX_MUTANT_TEMPLATE_NUM];

DECLARE_PER_CPU_PAGE_ALIGNED(struct sci_percpu_data, cpu_sci);

void sci_check_boottime_disable(void);

int sci_register_probe(struct sci_probe *p, struct sci_task_data *sci);

int sci_modify_parameter(struct sci_new_parameter *p,
			 struct sci_task_data *sci);

inline void sci_child_small_init(struct task_struct *tsk,
				 struct sci_task_data *sci);
int sci_child_init(struct task_struct *tsk, struct sci_task_data *sci);
void sci_child_exit(struct task_struct *tsk);
inline void sci_sync_kernel(pgd_t *runtime_pgd, pgd_t *root_pgd);

struct sci_task_data *sci_init(void);
void sci_exit(struct sci_task_data *sci);

void sci_function_modify_example(int a, int b);

bool sci_verify_and_map(struct pt_regs *regs, unsigned long addr,
			unsigned long hw_error_code);

void sci_clear_data(struct task_struct *tsk);

void mutant_unmap_dmm_pmd(unsigned long pmd_va);

void mutant_unmap_pmd_woflush(unsigned long pmd_va);

void mutant_flush_tlb(unsigned long pmd_va);

int sci_iso_rw_param(struct sci_task_data *, sci_rw_param_page **, unsigned);

void *private_vmalloc(unsigned long);
void private_vfree(void *);

struct page *get_pvp_cache_page(void);
int put_pvp_cache_page(struct page *);
void put_anon_pvp_cache_page(struct page *);
struct page *get_anon_pvp_cache_page(bool);
void free_unref_anon_pvp_cache_page_list(struct list_head *);

void *root_private_vmalloc(unsigned long, struct sci_task_data *);
void root_private_vfree(struct sci_task_data *, void *);
struct page *root_fetch_private_vmalloc_page(struct sci_private_vmalloc *,
					     unsigned long);

struct page *fetch_private_vmalloc_page(unsigned long);

void write_pvp_page(struct page *, struct page *);
inline void *pvmap_atomic(struct page *);
inline void pvunmap_atomic(void *);

#else /* CONFIG_SYSCALL_ISOLATION */

int sci_register_probe(struct sci_probe *p, struct task_struct *tsk,
		       struct sci_task_data *sci){};

static inline void sci_check_boottime_disable(void)
{
}

static inline bool sci_verify_and_map(struct pt_regs *regs, unsigned long addr,
				      unsigned long hw_error_code)
{
	return true;
}

static inline void sci_clear_data(void)
{
}

int sci_iso_rw_param(struct sci_task_data *, sci_rw_param_page **, unsigned)
{
	return 0;
}

#endif /* CONFIG_SYSCALL_ISOLATION */

#endif /* _ASM_X86_SCI_H */
