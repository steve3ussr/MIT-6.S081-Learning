#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/riscv.h"
#include "user/user.h"


int
main(int argc, char *argv[])
{
  sleep(1);
  exit(0);
}