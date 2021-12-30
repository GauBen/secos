/* GPLv2 (c) Airbus */
#include <cr.h>
#include <info.h>
#include <intr.h>
#include <debug.h>
#include <segmem.h>
#include <pagemem.h>

// Segmentation settings
#define RING0_CODE_ENTRY 1
#define RING0_DATA_ENTRY 2
#define RING3_DATA_ENTRY 3
#define RING3_CODE_ENTRY 4
#define TSS_ENTRY 5
#define GDT_LIMIT TSS_ENTRY + 1

/** Global descriptor table. */
__attribute__((aligned(8))) seg_desc_t gdt[GDT_LIMIT];
/** Task state segment. */
__attribute__((aligned(8))) tss_t tss;

// Paging settings
#define KERNEL_PGD_ADDR __page_directories_start__
#define KERNEL_PTB_ADDR __page_directories_start__ + 0x1000

#define USER_CODE_OFFSET 0x00000
#define USER_PGD_OFFSET 0xc0000
#define USER_PTB_OFFSET 0xc1000
#define USER_STACK_OFFSET 0xe0000
#define USER_STACK_START_OFFSET 0xefff0
#define USER_KERNEL_STACK_OFFSET 0xf0000
#define USER_KERNEL_STACK_START_OFFSET 0xffff0

extern info_t *info;
extern void *__page_directories_start__;

void setup_memory_segments()
{
  gdt_reg_t gdtr = {
    desc : gdt,
    limit : sizeof(gdt) - 1
  };

  memset(&tss, 0, sizeof tss);
  tss.s0.esp = get_ebp();
  tss.s0.ss = gdt_krn_seg_sel(RING0_DATA_ENTRY);

  gdt[0].raw = 0ULL;
  gdt_flat_dsc(&gdt[RING0_CODE_ENTRY], SEG_SEL_KRN, SEG_DESC_CODE_XR);
  gdt_flat_dsc(&gdt[RING0_DATA_ENTRY], SEG_SEL_KRN, SEG_DESC_DATA_RW);
  gdt_flat_dsc(&gdt[RING3_CODE_ENTRY], SEG_SEL_USR, SEG_DESC_CODE_XR);
  gdt_flat_dsc(&gdt[RING3_DATA_ENTRY], SEG_SEL_USR, SEG_DESC_DATA_RW);
  tss_dsc(&gdt[TSS_ENTRY], (offset_t)&tss);

  set_gdtr(gdtr);

  set_cs(gdt_krn_seg_sel(RING0_CODE_ENTRY));
  set_ss(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_ds(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_es(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_fs(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_gs(gdt_krn_seg_sel(RING0_DATA_ENTRY));
}

/** Enables memory paging with identity mapping. */
void setup_memory_pages(pde32_t *pgd, pte32_t *first_ptb, unsigned int flags)
{
  memset(pgd, 0, PAGE_SIZE);

  // Setup identity paging (see https://wiki.osdev.org/Identity_Paging)
  // From 0x00_0000 to 0x7f_ffff, with 2 page directory entries
  for (int entry = 0; entry <= 1; entry++)
  {
    // ptb address = base address + entry num * page size
    pte32_t *ptb = first_ptb + entry * 4096;
    for (int i = 0; i < 1024; i++)
      pg_set_entry(&ptb[i], flags, i + entry * 1024);
    // Add the page table to the page directory
    pg_set_entry(&pgd[entry], flags, page_nr(ptb));
  }

  // Enable paging (see https://wiki.osdev.org/Paging#Enabling)
  set_cr3(pgd);
}

void print_counter();
void increment_counter();

void handle_syscall()
{
  asm volatile("pusha\n");

  uint32_t *ptr;

  asm volatile(
      "mov %%eax, %0\n"
      : "=r"(ptr));

  // The address is right, but the value is currently overwritten
  // at some point in the execution
  debug("int 0x80 caught! Addr: %p, value: %d, ebp: %p\n", ptr, *ptr, get_ebp());

  asm volatile(
      "popa\n"
      "leave\n"
      "iret\n");
}

void setup_interruption_registry()
{
  idt_reg_t idtr;
  get_idtr(idtr);
  int_desc_t *idt = idtr.desc;

  int_desc(&idt[0x80], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_syscall);
  // Many thanks to Elies (@EyeXion) for this very simple line,
  // yet the cause of about two days of frustration
  idt[0x80].dpl = SEG_SEL_USR;
}

void setup_task(uint32_t user_task)
{
  debug("%p\n", user_task);
  setup_memory_pages(
      (pde32_t *)(user_task + USER_PGD_OFFSET),
      (pte32_t *)(user_task + USER_PTB_OFFSET),
      PG_USR | PG_RW);

  uint32_t *user_kernel_esp = (uint32_t *)(user_task + USER_KERNEL_STACK_START_OFFSET);

  // Prepare the stack for an `iret`
  *(user_kernel_esp - 1) = gdt_usr_seg_sel(RING3_DATA_ENTRY);
  *(user_kernel_esp - 2) = user_task + USER_STACK_START_OFFSET;
  *(user_kernel_esp - 3) = 0;
  *(user_kernel_esp - 4) = gdt_usr_seg_sel(RING3_CODE_ENTRY);
  *(user_kernel_esp - 5) = user_task;
}

void tp()
{
  setup_memory_pages((pde32_t *)KERNEL_PGD_ADDR, (pte32_t *)KERNEL_PTB_ADDR, PG_KRN | PG_RW);
  set_cr0(get_cr0() | CR0_PG | CR0_PE);

  setup_memory_segments();
  setup_interruption_registry();
  setup_task((uint32_t)increment_counter);
  setup_task((uint32_t)print_counter);

  set_ds(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_es(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_fs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_gs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  tss.s0.ss = gdt_krn_seg_sel(RING0_DATA_ENTRY);
  uint32_t user_kernel_esp = (uint32_t)increment_counter + USER_KERNEL_STACK_START_OFFSET - 20;
  tss.s0.esp = user_kernel_esp;
  set_tr(gdt_krn_seg_sel(TSS_ENTRY));

  set_esp(user_kernel_esp);
  asm volatile("iret\n");
}
