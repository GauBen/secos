/* GPLv2 (c) Airbus */
#include <cr.h>
#include <info.h>
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

#define gdt_flat_dsc(_entry, _ring, _type) \
  {                                        \
    (_entry)->raw = 0;                     \
    (_entry)->limit_1 = 0xffff;            \
    (_entry)->limit_2 = 0xf;               \
    (_entry)->type = _type;                \
    (_entry)->dpl = _ring;                 \
    (_entry)->d = 1;                       \
    (_entry)->g = 1;                       \
    (_entry)->s = 1;                       \
    (_entry)->p = 1;                       \
  }

#define tss_dsc(_entry, _addr)                \
  {                                           \
    raw32_t __addr = {.raw = _addr};          \
    (_entry)->raw = sizeof(tss_t);            \
    (_entry)->base_1 = __addr.wlow;           \
    (_entry)->base_2 = __addr._whigh.blow;    \
    (_entry)->base_3 = __addr._whigh.bhigh;   \
    (_entry)->type = SEG_DESC_SYS_TSS_AVL_32; \
    (_entry)->p = 1;                          \
  }

/** Global descriptor table. */
__attribute__((aligned(8))) seg_desc_t gdt[GDT_LIMIT];
/** Task state segment. */
__attribute__((aligned(8))) tss_t tss;

// Paging settings
#define PGD_ADDR 0x600000
#define PTB_ADDR 0x601000

extern info_t *info;

void setup_memory_segments()
{
  gdt_reg_t gdtr = {
    desc : gdt,
    limit : sizeof(gdt) - 1
  };

  gdt[0].raw = 0ULL;

  gdt_flat_dsc(&gdt[RING0_CODE_ENTRY], 0, SEG_DESC_CODE_XR);
  gdt_flat_dsc(&gdt[RING0_DATA_ENTRY], 0, SEG_DESC_DATA_RW);
  gdt_flat_dsc(&gdt[RING3_CODE_ENTRY], 3, SEG_DESC_CODE_XR);
  gdt_flat_dsc(&gdt[RING3_DATA_ENTRY], 3, SEG_DESC_DATA_RW);

  set_gdtr(gdtr);

  set_cs(gdt_krn_seg_sel(RING0_CODE_ENTRY));
  set_ss(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_ds(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_es(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_fs(gdt_krn_seg_sel(RING0_DATA_ENTRY));
  set_gs(gdt_krn_seg_sel(RING0_DATA_ENTRY));
}

/** Enables memory paging with identity mapping. */
void setup_memory_pages()
{
  pde32_t *pgd = (pde32_t *)PGD_ADDR;
  memset(pgd, 0, PAGE_SIZE);

  // Setup identity paging (see https://wiki.osdev.org/Identity_Paging)
  // From 0x00_0000 to 0x7f_ffff, with 2 page directory entries
  for (int entry = 0; entry <= 1; entry++)
  {
    // ptb address = base address + entry num * page size
    pte32_t *ptb = (pte32_t *)(PTB_ADDR + entry * 4096);
    for (int i = 0; i < 1024; i++)
      pg_set_entry(&ptb[i], PG_KRN | PG_RW, i + entry * 1024);
    // Add the page table to the page directory
    pg_set_entry(&pgd[entry], PG_KRN | PG_RW, page_nr(ptb));
  }

  // Enable paging (see https://wiki.osdev.org/Paging#Enabling)
  set_cr3(pgd);
  set_cr0(get_cr0() | CR0_PG | CR0_PE);
}

void userland()
{
  // asm volatile("int 0x80;");
  while (1)
    ;
}

void test_user()
{
  set_ds(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_es(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_fs(gdt_usr_seg_sel(RING3_DATA_ENTRY));
  set_gs(gdt_usr_seg_sel(RING3_DATA_ENTRY));

  memset(&tss, 0, sizeof tss);
  tss.s0.esp = get_ebp();
  tss.s0.ss = gdt_krn_seg_sel(RING0_DATA_ENTRY);
  tss_dsc(&gdt[TSS_ENTRY], (offset_t)&tss);
  set_tr(gdt_krn_seg_sel(TSS_ENTRY));

  asm volatile(
      "push %0    \n" // ss
      "push %%ebp \n" // esp
      "pushf      \n" // eflags
      "push %1    \n" // cs
      "push %2    \n" // eip
      "iret" ::
          "i"(gdt_usr_seg_sel(RING3_DATA_ENTRY)), //ss
      "i"(gdt_usr_seg_sel(RING3_CODE_ENTRY)),     //cs
      "r"(&userland)                              //eip
  );
}

void tp()
{
  // setup_memory_pages();
  setup_memory_segments();
  test_user();
}
