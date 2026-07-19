#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "sysinfo.h"

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
  uint64 avg_load[3] = {11, 45, 14};


  // prepare struct
  struct sysinfo res;
  res.freemem = mem_free_bytes;
  res.nproc = (uint64) nproc;
  res.load[0] = avg_load[0];
  res.load[1] = avg_load[1];
  res.load[2] = avg_load[2];
  printf("[sys_sysinfo]\tload:\t%d, %d, %d processes\n", res.load[0], res.load[1], res.load[2]);

  // copyout
  struct proc *p = myproc();
  if(copyout(p->pagetable, va, (char *)&res, sizeof(res)) < 0)
      return -1;
    return 0;
}
