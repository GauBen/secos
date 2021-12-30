# Virtual and physical addresses

## Physical addresses

| Address   | Content          |
| --------- | ---------------- |
| 0010 0000 | Multiboot header |
| 0010 0010 | Kernel stack     |
| 0010 2010 | Kernel           |
| 0040 0000 | Task 1           |
| 0050 0000 | Task 2           |
| 0080 0000 | Shared memory    |
| 07ff ffff | Last address     |

## Task addresses

| Offset   | Content                           |
| -------- | --------------------------------- |
| 0x0 0000 | Code                              |
| 0xc 0000 | User page directory               |
| 0xc 1000 | User page tables                  |
| 0xe 0000 | User stack (starts at 0xe fff0)   |
| 0xf 0000 | Kernel stack (starts at 0xf fff0) |
| 0xf ffff | Last address                      |
