#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <asm/special_insns.h>
#include <asm/sci.h>
#include <asm/pgalloc.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define BUF_SIZE 1024

typedef void (*foo)(void);

SYSCALL_DEFINE2(sci_write_dmesg, const char __user *, ubuf, size_t, count)
{
	char buf[BUF_SIZE];

	if (!ubuf || count >= BUF_SIZE)
		return -EINVAL;

	buf[count] = '\0';
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	printk("%s\n", buf);

	return count;
}

SYSCALL_DEFINE2(sci_write_dmesg_bad, const char __user *, ubuf, size_t, count)
{
	unsigned long addr = (unsigned long)(void *)hugetlb_reserve_pages;
	char buf[BUF_SIZE];
	foo func1;

	addr += 0xc5;
	func1 = (foo)(void *)addr;
	func1();

	if (!ubuf || count >= BUF_SIZE)
		return -EINVAL;

	buf[count] = '\0';
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	printk("%s\n", buf);

	return count;
}

/********************************************************************
Victim code.
********************************************************************/
char* sci_secret = "The Magic Words are Squeamish Ossifrage.";
uint8_t sci_unused0[256 * 512];
unsigned int sci_array1_size = 16;
uint8_t sci_unused1[64];
uint8_t sci_array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t sci_unused2[64];
uint8_t sci_array2[256 * 512];

struct page *target_pages;
unsigned long target_cache_regions_start;
unsigned long secret_start;
unsigned long offset;
uint8_t sci_temp = 0; /* Used so compiler won't optimize out victim_function() */

/*victim function now used to test function modification
* use sci_function_modify_example()
*/


static void init_one_pvp_cache(void)
{
	if (target_pages) {return;}
	
	target_pages = alloc_pages(GFP_KERNEL, 9);	//per_pvp_cache_order 9
	if (!target_pages) {
		mutant_printk(
			MUTANT_ERR,
			"secure test error: failed to alloc new pvp cache\n");
		return;
	}
	//split_huge_page(cache->pages);
	target_cache_regions_start =
		(unsigned long)__va(page_to_phys(target_pages));
		
	secret_start = target_cache_regions_start + 0x420; //0x420 ramdom
	
	memcpy((void *)secret_start, (void *)sci_secret, 40);	
	//mutant_unmap_dmm_pmd(cache_for_test->cache_regions_start);

	printk("2MB hugepage init, start: 0x%lx\n", target_cache_regions_start);

	return;
}

#define SECURE_TEST_INIT 1
#define SECURE_TEST_UNMAP_wo_flush 2
#define SECURE_TEST_VICTIM 3
#define SECURE_TEST_TOUCH_SECRET 4
#define SECURE_TEST_FLUSH_ARRAY_2 5
#define SECURE_TEST_FLUSH_ARRAY_1_size 6
#define SECURE_TEST_SWITCH_TARGET 7
#define SECURE_TEST_UNMAP_flush_tlb 8

static noinline void sci_flush_array1_size(void){
	//_mm_clflush(&sci_array1_size);
	clflush_cache_range(&sci_array1_size, 4);
	return;
}

static noinline void sci_victim_function(unsigned long x){
	//clflush_cache_range(&sci_array1_size, 4);
	if (x < sci_array1_size)
		sci_temp &= sci_array2[sci_array1[x] * 512];
	//sci_function_modify_example(3,2);
	return;
}

static void sci_init_array2(int x){
	size_t i = 0;
	for (i = 0; i < sizeof(sci_array2); i++)
		sci_array2[i] = x; /* write to array2 so in RAM not copy-on-write zero pages */
		
	return;
}

static void sci_flush_array2(void){
	clflush_cache_range(sci_array2, 256*512);
	return;
}

extern void mutant_unmap_dmm_pmd(unsigned long);

unsigned long ksys_sci_secure_test(unsigned cmd, unsigned long parameter)
{
	unsigned long ret = 0;
	switch (cmd) {
	case SECURE_TEST_INIT:
		init_one_pvp_cache();
		sci_init_array2(34);
		ret = (unsigned long)secret_start - (unsigned long)sci_array1;
		offset = ret;
		printk("array1 at: 0x%lx\n", (unsigned long)sci_array1);
		printk("array2 at: 0x%lx\n", (unsigned long)sci_array2);
		printk("sci_secret at: 0x%lx\n", (unsigned long)sci_secret);
		printk("ret: 0x%lx\n", (unsigned long)ret);
		break;
	case SECURE_TEST_TOUCH_SECRET:
		int i;
		printk("secret at: 0x%lx\n", (unsigned long)sci_array1 + offset);
		for (i = 0; i <= 40; i++){
			printk("%c", (sci_array1[i + offset] > 31 && sci_array1[i + offset] < 127 ? sci_array1[i + offset] : '?'));
		}
		printk("\n");
		break;
	case SECURE_TEST_UNMAP_wo_flush:
		mutant_unmap_pmd_woflush(target_cache_regions_start);
		break;
	case SECURE_TEST_VICTIM:
		sci_victim_function(parameter);
		break;
	case SECURE_TEST_FLUSH_ARRAY_2:
		sci_flush_array2();
		break;
	case SECURE_TEST_FLUSH_ARRAY_1_size:
		sci_flush_array1_size();
		break;
	case SECURE_TEST_SWITCH_TARGET:
		ret = (unsigned long)sci_secret - (unsigned long)sci_array1;
		offset = ret;
		printk("array1 at: 0x%lx\n", (unsigned long)sci_array1);
		printk("array2 at: 0x%lx\n", (unsigned long)sci_array2);
		printk("sci_secret at: 0x%lx\n", (unsigned long)sci_secret);
		break;
	case SECURE_TEST_UNMAP_flush_tlb:
		mutant_flush_tlb(target_cache_regions_start);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}


//sci_victim_function
SYSCALL_DEFINE2(ksys_sci_secure_test, unsigned, cmd, unsigned long, x){
	return ksys_sci_secure_test(cmd, x);
}

SYSCALL_DEFINE1(ksys_sci_secure_get_array2, unsigned long, x){
	if( x < 256*512 && x >=0)
		return sci_array2[x];
		
	return 0;	
	//return (unsigned long)sci_secret;
}



