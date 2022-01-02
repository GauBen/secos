/* GPLv2 (c) Airbus */
#include <cr.h>
#include <asm.h>
#include <info.h>
#include <intr.h>
#include <debug.h>
#include <segmem.h>
#include <pagemem.h>
#include "userland.h"

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
#define KERNEL_PGD_ADDR 0x200000
#define KERNEL_PTB_ADDR KERNEL_PGD_ADDR + 0x1000

#define USER_CODE_OFFSET 0x00000
#define USER_PGD_OFFSET 0xc0000
#define USER_PTB_OFFSET 0xc1000
#define USER_STACK_OFFSET 0xe0000
#define USER_STACK_START_OFFSET 0xefff0
#define USER_KERNEL_STACK_OFFSET 0xf0000
#define USER_KERNEL_STACK_START_OFFSET 0xffff0

unsigned int num_tasks = 0;
uint32_t tasks[4] = {};
int current_task = -1;

/** Enables memory segmentation. */
void setup_memory_segments()
{
  gdt_reg_t gdtr = {
    desc : gdt,
    limit : sizeof(gdt) - 1
  };

  gdt[0].raw = 0ULL;
  memset(&tss, 0, sizeof tss);

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

/** Handles `int 0x80`, i.e. syscall interrupts. */
void handle_syscall()
{
  asm volatile("pusha\n");

  uint32_t *ptr;

  asm volatile(
      "mov %%eax, %0\n"
      : "=r"(ptr));

  debug("Counter: %d\n", *ptr);

  asm volatile(
      "popa\n"
      "leave\n"
      "iret\n");
}

/** Simple trampoline code for the real handler. */
void handle_clock_tick_asm();
asm(
    "handle_clock_tick_asm:\n"
    "pusha\n"
    "call handle_clock_tick\n"
    "mov %eax, %esp\n"
    "popa\n"
    "iret\n");

/** Simple round-robin scheduler. */
void handle_clock_tick()
{
  debug("tick\n");

  if (num_tasks <= 0)
    return;

  current_task = (current_task + 1) % num_tasks;
  uint32_t task = tasks[current_task];

  uint32_t user_kernel_esp = task + USER_KERNEL_STACK_START_OFFSET;
  uint32_t esp = user_kernel_esp - (4 * 13); // 13 entries were pushed to the stack

  tss.s0.ss = gdt_krn_seg_sel(RING0_DATA_ENTRY);
  tss.s0.esp = user_kernel_esp;
  set_cr3(task + USER_PGD_OFFSET);

  // Give the new esp back to the trampoline
  asm volatile(
      "mov %0, %%eax\n"
      :
      : "r"(esp));
}

/** Replaces some interruption handlers (32 and 0x80) with new ones. */
void setup_interruption_registry()
{
  idt_reg_t idtr;
  get_idtr(idtr);
  int_desc_t *idt = idtr.desc;

  int_desc(&idt[0x80], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_syscall);
  // Many thanks to Elies (@EyeXion) for this very simple line,
  // yet the cause of about two days of frustration
  idt[0x80].dpl = SEG_SEL_USR;

  // Preemptive multitasking
  int_desc(&idt[32], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_clock_tick_asm);
  idt[32].dpl = SEG_SEL_USR;
}

/** Prepares memory pages and kernel stack for a user task. */
void setup_task(uint32_t user_task)
{
  tasks[num_tasks] = user_task;
  num_tasks++;

  setup_memory_pages(
      (pde32_t *)(user_task + USER_PGD_OFFSET),
      (pte32_t *)(user_task + USER_PTB_OFFSET),
      PG_USR | PG_RW);

  uint32_t *user_kernel_esp = (uint32_t *)(user_task + USER_KERNEL_STACK_START_OFFSET);

  // Prepare the stack for an `iret`
  *(user_kernel_esp - 1) = gdt_usr_seg_sel(RING3_DATA_ENTRY);   // SS
  *(user_kernel_esp - 2) = user_task + USER_STACK_START_OFFSET; // ESP
  *(user_kernel_esp - 3) = EFLAGS_IF;                           // Flags
  *(user_kernel_esp - 4) = gdt_usr_seg_sel(RING3_CODE_ENTRY);   // CS
  *(user_kernel_esp - 5) = user_task;                           // EIP
}

/** Kernel entry-point. */
void tp()
{
  setup_memory_pages((pde32_t *)KERNEL_PGD_ADDR, (pte32_t *)KERNEL_PTB_ADDR, PG_KRN | PG_RW);
  set_cr0(get_cr0() | CR0_PG | CR0_PE);

  setup_memory_segments();
  setup_task((uint32_t)increment_counter);
  setup_task((uint32_t)print_counter);

  // Set shared memory up
  {
    // 0x800000 to 0x800000
    pde32_t *pgd = (pde32_t *)(increment_counter + USER_PGD_OFFSET);
    pte32_t *ptb = (pte32_t *)(increment_counter + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd[2], PG_USR | PG_RW, page_nr(ptb));
    pg_set_entry(&ptb[0], PG_USR | PG_RW, page_nr(0x800000));
  }
  {
    // 0x801000 to 0x800000
    pde32_t *pgd = (pde32_t *)(print_counter + USER_PGD_OFFSET);
    pte32_t *ptb = (pte32_t *)(print_counter + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd[2], PG_USR | PG_RW, page_nr(ptb));
    pg_set_entry(&ptb[1], PG_USR | PG_RW, page_nr(0x800000));
  }

  set_ds(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_es(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_fs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_gs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_tr(gdt_krn_seg_sel(TSS_ENTRY));
  tss.s0.ss = gdt_krn_seg_sel(RING0_DATA_ENTRY);
  tss.s0.esp = get_esp();

  // Start the first user task
  setup_interruption_registry();
  asm volatile("int $32;\n");
}
