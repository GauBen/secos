#include <types.h>
#include <syscall.h>
#include "userland.h"

__attribute__((section(".user1"))) void increment_counter()
{
  uint32_t x = 1;
  sys_counter(&x);
  asm volatile("int $0x81\n");
  x += 1;
  sys_counter(&x);
  asm volatile("int $0x81\n");
  x += 2;
  sys_counter(&x);
  asm volatile("int $0x81\n");
  while (1)
    ;
}

__attribute__((section(".user2"))) void print_counter()
{
  uint32_t x = 2;
  sys_counter(&x);
  sys_counter(&x);
  asm volatile("int $0x81\n");
  x += 3;
  sys_counter(&x);
  sys_counter(&x);
  asm volatile("int $0x81\n");
  x += 4;
  sys_counter(&x);
  sys_counter(&x);
  while (1)
    ;
}
