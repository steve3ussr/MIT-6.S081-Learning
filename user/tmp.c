#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/riscv.h"
#include "user/user.h"


int
main(int argc, char *argv[])
{
  char *addr = sbrk(7);
  strcpy(addr, "114514\0");
  printf("[user space] addr(%p) = %s\n", addr, addr);

 

  addr = sbrk(-7);
  printf("[user space] addr(%p) = %s\n", addr, addr);

  exit(0);
}