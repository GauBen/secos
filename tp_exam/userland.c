#include <types.h>
#include <syscall.h>
#include "userland.h"

__attribute__((section(".user1"))) void increment_counter()
{
  uint32_t *x = (uint32_t *)0x800000;
  *x = 10;
  asm volatile("int $0x81\n");
  while (1)
    ;
}

__attribute__((section(".user2"))) void print_counter()
{
  uint32_t *x = (uint32_t *)0x801000;
  *x += 1;
  sys_counter(x);
  while (1)
    ;
}
