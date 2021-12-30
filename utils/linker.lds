/* GPLv2 (c) Airbus */
OUTPUT_FORMAT("elf32-i386","elf32-i386","elf32-i386");
OUTPUT_ARCH("i386")

ENTRY(entry)

PHDRS
{
  phboot  PT_LOAD FLAGS (7);
  phstack PT_LOAD FLAGS (6);
  phsetup PT_LOAD FLAGS (7);
}

SECTIONS
{
  /* Lowest legal address */
  . = 0x100000;
  .mbh      : { KEEP(*(.mbh)) . = ALIGN(4);     } : phboot
  .stack    : { KEEP(*(.stack))                 } : phstack

  __kernel_start__ = .;

  .idt_jmp  : { KEEP(*(.idt_jmp))               } : phsetup
  .text     : { *(.text)                        } : phsetup
  .rodata   : { *(.rodata)                      } : phsetup
  .data     : { *(.data)                        } : phsetup
  .bss      : { *(.bss COMMON)                  } : phsetup
  /DISCARD/ : { *(.note* .indent .comment)      } : phsetup

  /* Kernel end should be around 0x10bfff */
  __kernel_end__ = .;

  /* All page directories/tables will be between 0x30_0000 and 0x3f_ffff */
  . = 0x300000;
  __page_directories_start__ = .;

  /* Task 1 will be between 0x40_0000 and 0x4f_ffff */
  . = 0x400000;
  __task_start__ = .;
  .user1 : { KEEP(*(.user1)) } : phsetup

  /* Task 2 will be between 0x50_0000 and 0x5f_ffff */
  . = 0x500000;
  .user2 : { KEEP(*(.user2)) } : phsetup

  /* This allows for two more tasks to be compiled with the kernel */

  /* Shared memory will be between 0x80_0000 and 0xff_ffff */
  . = 0x800000;
  __shared_memory_start__ = .;
}
