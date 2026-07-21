#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "sysinfo.h"

extern long loads[3];


void itoa_load(char *s, long i_x100) {
  if ((i_x100 < 0) || (i_x100 >= 10000)) {
    strncpy(s, "<MAX>", 5);
    s[5] = '\0';
    return;
  }

  int i_x100_int = i_x100 / 100;
  int i_x100_frg = i_x100 % 100;
  // printf("int=%d, frg=%d\n", i_x100_int, i_x100_frg);
  if (i_x100_int < 10) {
    s[0] = ' ';
    s[1] = '0' + i_x100_int;
  } else if (i_x100_int <= 99) {
    s[0] = '0' + (i_x100_int/10);
    s[1] = '0' + (i_x100_int%10);
  } else {
    strncpy(s, "??", 2);
  }
  
  s[2] = '.';

  if (i_x100_frg < 10) {
    s[3] = '0';
    s[4] = '0' + i_x100_frg;
  } else if (i_x100_frg <= 99) {
    s[3] = '0' + (i_x100_frg/10);
    s[4] = '0' + (i_x100_frg%10);
  } else {
    strncpy(s+3, "??", 2);
  }
  s[5] = '\0';
}

uint64
sys_exit(void)
{
  int n;
  if(argint(0, &n) < 0)
    return -1;
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  if(argaddr(0, &p) < 0)
    return -1;
  return wait(p);
}

uint64
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64 sys_trace(void) {
  int mask;

  // argint: Fetch the nth 32-bit system call argument.
  // int argint(int n, int *ip)
  if(argint(0, &mask) < 0) return -1;

  // 最多可以监控31个syscall (第0位也没用, 因为syscall num从1开始)
  // 例如: mask=32, 2^5, 0x20, 对应 syscall 5 read
  // 允许溢出, 表现为mask为负数
  // printf("trace mask: 0x%x\n", mask);

  // 获取proc, 记录mask
  myproc()->tracemask = (uint)mask;
  return 0;
}

uint64 sys_sysinfo(void) {
  uint64 va;
  if(argaddr(0, &va) < 0) return -1;
  // printf("[sys_sysinfo]\targ 1:\t0x%x\n", va);

  // get freemem
  uint64 mem_free_bytes = kstat_free();
  // printf("[sys_sysinfo]\tfree:\t%d Bytes\n", mem_free_bytes);
  // printf("[sys_sysinfo]\tfree:\t%d KB\n", mem_free_bytes>>10);
  // printf("[sys_sysinfo]\tfree:\t%d MB\n", mem_free_bytes>>20);

  // get nproc
  int nproc = stat_nproc();
  // printf("[sys_sysinfo]\tnrpoc:\t%d processes\n", nproc);

  // get avg load (1min, 5min, 15min)



  // prepare struct
  struct sysinfo res;
  res.freemem = mem_free_bytes;
  res.nproc = (uint64) nproc;
  
  int load1_x100 = loads[0]/(LOAD_FACTOR/100);
  int load5_x100 = loads[1]/(LOAD_FACTOR/100);
  int load15_x100 = loads[2]/(LOAD_FACTOR/100);
  // printf("load1_x100=%d, load5_x100=%d, load15_x100=%d\n", load1_x100, load5_x100, load15_x100);

  itoa_load(res.load1, load1_x100);
  itoa_load(res.load5, load5_x100);
  itoa_load(res.load15, load15_x100);
  // printf("load1=%s, load5=%s, load15=%s\n", res.load1, res.load5, res.load15);
  // copyout
  struct proc *p = myproc();
  if(copyout(p->pagetable, va, (char *)&res, sizeof(res)) < 0)
      return -1;
    return 0;
}
