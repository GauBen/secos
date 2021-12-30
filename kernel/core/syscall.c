#include <types.h>
#include <syscall.h>

void sys_counter(uint32_t *counter)
{
  asm volatile(
      "mov %0, %%eax\n"
      "int $0x80\n"
      :
      : "r"(counter));
}
