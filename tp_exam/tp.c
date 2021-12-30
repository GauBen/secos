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
#define KERNEL_PGD_ADDR 0x600000
#define KERNEL_PTB_ADDR 0x601000

#define USER1_PGD_ADDR 0x603000
#define USER1_PTB_ADDR 0x604000

extern info_t *info;

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

void test_user()
{
  set_ds(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_es(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_fs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_gs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_tr(gdt_krn_seg_sel(TSS_ENTRY));

  setup_memory_pages((pde32_t *)USER1_PGD_ADDR, (pte32_t *)USER1_PTB_ADDR, PG_USR | PG_RW);

  tss.s0.esp = 0x7f0000;

  asm volatile(
      "push %0\n" // ss
      "push %1\n" // esp
      "pushf\n"   // eflags
      "push %2\n" // cs
      "push %3\n" // eip
      "iret\n"
      :
      : "irm"(gdt_usr_seg_sel(RING3_DATA_ENTRY)), // ss
        "irm"(0x7c0000),                          // esp
        "irm"(gdt_usr_seg_sel(RING3_CODE_ENTRY)), // cs
        "irm"(&print_counter)                     // eip
  );
}

void handle_syscall()
{
  asm volatile("pusha\n");

  uint32_t *ptr;

  asm volatile(
      "mov %%eax, %0\n"
      : "=r"(ptr));

  // The address is right, but the value is currently overwritten
  // at some point in the execution
  debug("int 0x80 caught! Addr: %p, value: %d\n", ptr, *ptr);

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

void tp()
{
  debug("%p %p\n", increment_counter, print_counter);

  setup_memory_pages((pde32_t *)KERNEL_PGD_ADDR, (pte32_t *)KERNEL_PTB_ADDR, PG_KRN | PG_RW);
  set_cr0(get_cr0() | CR0_PG | CR0_PE);

  setup_memory_segments();
  setup_interruption_registry();
  test_user();
}
