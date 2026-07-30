#include "kernel/param.h"
#include "kernel/fcntl.h"
#include "kernel/types.h"
#include "kernel/riscv.h"
#include "user/user.h"

#define unsigned int uint

void err(char *s){
    printf("%s\n", s);
    exit(1);
}

int main()
{
  char *buf = malloc(32 * PGSIZE);;
  uint abits, dbits;
  (void)dbits;
  if (pgaccess(buf, 32, &abits) < 0)
    err("pgaccess failed");

  buf[PGSIZE * 1] += 1;
  buf[PGSIZE * 2] += 1;
  volatile char tmp = buf[PGSIZE * 30];
  (void) tmp;

  if (pgaccess(buf, 32, &abits) < 0)
    err("pgaccess failed");

  printf("abits: %p\n", abits);
  if (abits != ((1 << 1) | (1 << 2) | (1 << 30)))
    err("incorrect access bits set");

  /* ---------------------------- */

  if (pgdirty(buf, 32, &dbits) < 0)
    err("pgdirty failed");
  buf[PGSIZE * 11] += 1;
  buf[PGSIZE * 14] += 1;
  buf[PGSIZE * 15] += 1;

  if (pgdirty(buf, 32, &dbits) < 0)
    err("pgdirty failed");

  printf("dbits: %p\n", dbits);
  if (dbits != ((1 << 11) | (1 << 14) | (1 << 15)))
    err("incorrect dirty bits set");

  /* ---------------------------- */

  free(buf);
  printf("pgaccess + pgdirty test: OK\n");
  exit(0);
}
