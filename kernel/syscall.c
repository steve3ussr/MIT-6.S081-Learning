#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"

// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz)
    return -1;
  if(copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  int err = copyinstr(p->pagetable, buf, addr, max);
  if(err < 0)
    return err;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
int
argint(int n, int *ip)
{
  *ip = argraw(n);
  return 0;
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
int
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
  return 0;
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  if(argaddr(n, &addr) < 0)
    return -1;
  return fetchstr(addr, buf, max);
}

extern uint64 sys_chdir(void);
extern uint64 sys_close(void);
extern uint64 sys_dup(void);
extern uint64 sys_exec(void);
extern uint64 sys_exit(void);
extern uint64 sys_fork(void);
extern uint64 sys_fstat(void);
extern uint64 sys_getpid(void);
extern uint64 sys_kill(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_mknod(void);
extern uint64 sys_open(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_unlink(void);
extern uint64 sys_wait(void);
extern uint64 sys_write(void);
extern uint64 sys_uptime(void);
extern uint64 sys_trace(void);
extern uint64 sys_sysinfo(void);

static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork,           // sysproc.c
[SYS_exit]    sys_exit,           // sysproc.c
[SYS_wait]    sys_wait,           // sysproc.c
[SYS_pipe]    sys_pipe,       // sysfile.c
[SYS_read]    sys_read,       // sysfile.c
[SYS_kill]    sys_kill,           // sysproc.c
[SYS_exec]    sys_exec,       // sysfile.c
[SYS_fstat]   sys_fstat,      // sysfile.c
[SYS_chdir]   sys_chdir,      // sysfile.c
[SYS_dup]     sys_dup,        // sysfile.c
[SYS_getpid]  sys_getpid,         // sysproc.c
[SYS_sbrk]    sys_sbrk,           // sysproc.c
[SYS_sleep]   sys_sleep,          // sysproc.c
[SYS_uptime]  sys_uptime,         // sysproc.c
[SYS_open]    sys_open,       // sysfile.c
[SYS_write]   sys_write,      // sysfile.c
[SYS_mknod]   sys_mknod,      // sysfile.c
[SYS_unlink]  sys_unlink,     // sysfile.c
[SYS_link]    sys_link,       // sysfile.c
[SYS_mkdir]   sys_mkdir,      // sysfile.c
[SYS_close]   sys_close,      // sysfile.c
[SYS_trace]   sys_trace,          // sysproc.c
[SYS_sysinfo]   sys_sysinfo,      // sysproc.c
};

static char *syscall_names[] = {
[SYS_fork]    "fork",
[SYS_exit]    "exit",
[SYS_wait]    "wait",
[SYS_pipe]    "pipe",
[SYS_read]    "read",
[SYS_kill]    "kill",
[SYS_exec]    "exec",
[SYS_fstat]   "fstat",
[SYS_chdir]   "chdir",
[SYS_dup]     "dup",
[SYS_getpid]  "getpid",
[SYS_sbrk]    "sbrk",
[SYS_sleep]   "sleep",
[SYS_uptime]  "uptime",
[SYS_open]    "open",
[SYS_write]   "write",
[SYS_mknod]   "mknod",
[SYS_unlink]  "unlink",
[SYS_link]    "link",
[SYS_mkdir]   "mkdir",
[SYS_close]   "close",
[SYS_trace]   "trace",
[SYS_sysinfo] "sysinfo"
};

static char *desc[] = {
[SYS_close]   "fd", 
[SYS_dup]     "fd", 
[SYS_kill]    "pid", 
[SYS_sleep]   "ticks", 
[SYS_trace]   "mask", 
[SYS_sbrk]    "bytes"
};

void 
print_syscall_args(int syscall_num, struct proc *p)
{
  int fd0, mode, n;
  uint64 fdarray, addr;
  char path[MAXPATH], path2[MAXPATH];  

  switch (syscall_num) {
    case SYS_fork:
    case SYS_getpid:
    case SYS_uptime:
      printf("[trace-args] %d: syscall %s() -> ", p->pid, syscall_names[syscall_num]);
      break;

    case SYS_exit:
      printf("[trace-args] %d: syscall %s(int status=%d) -> (exit)\n", p->pid, syscall_names[syscall_num], (int)argraw(0));
      break;
    case SYS_close:
    case SYS_dup:
    case SYS_kill:
    case SYS_sleep:
    case SYS_trace:
    case SYS_sbrk:
      printf("[trace-args] %d: syscall %s(int %s=%d) -> ", p->pid, syscall_names[syscall_num], desc[syscall_num], (int)argraw(0));
      break;

    case SYS_wait:
      printf("[trace-args] %d: syscall %s(int *wstatus=%p) -> ", p->pid, syscall_names[syscall_num], argraw(0));
      break;
    case SYS_pipe:
      argaddr(0, &fdarray);
      printf("[trace-args] %d: syscall %s(int pipefd[2]@%p) -> ", p->pid, syscall_names[syscall_num], fdarray);
      break;

    case SYS_write:
    case SYS_read:
      argint(0, &fd0);
      argaddr(1, &addr);
      argint(2, &n);   
      printf("[trace-args] %d: syscall %s(int fd=%d, uint64 addr=%p, int n=%d) -> ", p->pid, syscall_names[syscall_num], fd0, addr, n);
      break;


    case SYS_exec: 
      argaddr(1, &addr);  // addr of char **argv
      char tmp[MAXPATH];
      uint64 straddr=0;   // addr of argv[i]
      for (int i=0; i<MAXARG; i++) {
        copyin(p->pagetable, (char *)(&straddr), addr+i*sizeof(char *), sizeof(uint64));
        if (straddr == 0) break;

        for (int i=0; i<MAXPATH; i++) {
          copyin(p->pagetable, &(tmp[i]), straddr+i*sizeof(char), sizeof(char));
          if (tmp[i]== '\0') break;
        }

        printf("%p argv[%d] -> %p -> %s\n", addr+i*sizeof(char *), i, straddr, tmp);
      }

      argstr(0, path, MAXPATH);
      printf("[trace-args] %d: syscall %s(path=%s, argv@%p) -> ", p->pid, syscall_names[syscall_num], path, addr);
      break;

    case SYS_open: 
      argstr(0, path, MAXPATH);
      argint(1, &mode);
      printf("[trace-args] %d: syscall %s(char *path=%s, mode=%d) -> ", 
             p->pid, 
             syscall_names[syscall_num], 
             path, 
             mode);
      break;

    // unverified
    case SYS_mknod:
      argstr(0, path, MAXPATH);
      printf("[trace-args] %d: syscall %s(char *path=%s, short major=%d, short minor=%d) -> ", 
             p->pid, 
             syscall_names[syscall_num], 
             path, 
             (int)argraw(1), 
             (int)argraw(2));
      break;

    case SYS_unlink:
    case SYS_mkdir:
    case SYS_chdir:
      argstr(0, path, MAXPATH);
      printf("[trace-args] %d: syscall %s(char *path=%s) -> ", 
             p->pid, 
             syscall_names[syscall_num], 
             path);
      break;

    case SYS_fstat:
      argaddr(1, &addr);
      printf("[trace-args] %d: syscall %s(int fd=%d, struct stat *p=%p) -> ", 
             p->pid, 
             syscall_names[syscall_num], 
             (int)argraw(0), 
             addr);
      break;

    case SYS_link:
      argstr(0, path, MAXPATH);
      argstr(1, path2, MAXPATH);
      printf("[trace-args] %d: syscall %s(char *old_path=%s, char *new_path=%s) -> ", 
             p->pid, 
             syscall_names[syscall_num], 
             path, 
             path2);
      break;
    
    case SYS_sysinfo:
      argaddr(0, &addr);
      printf("[trace-args] %d: syscall %s(struct sysinfo *p=%p) -> ", 
             p->pid, 
             syscall_names[syscall_num], 
             addr);
      break;

    default: 
      printf("[trace-args] UNKNOWN SYSCALL NUMBER\n");
      break;
  }
  
}

void
syscall(void)
{
  int num;
  struct proc *p = myproc();

  num = p->trapframe->a7;
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {

      
      if ((1 << num) & (p->tracemask)) {
        print_syscall_args(num, p);
      }
      // if num==SYS_trace, and trace SYS_trace itself, should also print
      else if ((num == SYS_trace)) {
        if ((int)argraw(0) & (1 << num)) {
          print_syscall_args(num, p);
        }
      }

    p->trapframe->a0 = syscalls[num]();

    // do not print if call SYS_exit
    if (((1 << num) & (p->tracemask)) && (num != SYS_exit)) {
      printf("%d\n", p->trapframe->a0);
    }

  } else {
    printf("%d %s: unknown sys call %d\n",
            p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
