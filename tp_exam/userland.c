#include <types.h>
#include <syscall.h>

__attribute__((section(".user1"))) void increment_counter()
{
}

__attribute__((section(".user2"))) void print_counter()
{
  uint32_t x = 10;
  sys_counter(&x);
  x++;
  sys_counter(&x);
  x++;
  sys_counter(&x);
  while (1)
    ;
}
