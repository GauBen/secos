/* GPLv2 (c) Airbus */
#include <cr.h>
#include <info.h>
#include <debug.h>
#include <pagemem.h>

#define PGD_ADDR 0x600000
#define PTB_ADDR 0x601000

extern info_t *info;

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

void tp()
{
  setup_memory_pages();
}
