#include <types.h>
#include <syscall.h>
#include "userland.h"

__attribute__((section(".user1"))) void increment_counter()
{
  uint32_t *x = (uint32_t *)0x800000;
  *x = 0;
  while (1)
  {
    (*x)++;
  }
}

__attribute__((section(".user2"))) void print_counter()
{
  uint32_t *x = (uint32_t *)0x801000;
  while (1)
  {
    sys_counter(x);
  }
}
