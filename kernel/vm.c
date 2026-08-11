#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"


/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // map kernel stacks
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}


// Duplicate a kernel page table for process.
// Return 0 if failed, return pagetable_t if success
pagetable_t
pvmmake(void)
{
  pagetable_t pgtbl = (pagetable_t)kalloc();
  if (pgtbl == 0) return 0;
  memset(pgtbl, 0, PGSIZE);

  if (pvmmap(pgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W) != 0)                                goto err;
  if (pvmmap(pgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W) != 0)                            goto err;
  if (pvmmap(pgtbl, PLIC, PLIC, 0x400000, PTE_R | PTE_W) != 0)                                goto err;
  if (pvmmap(pgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X) != 0)          goto err;
  if (pvmmap(pgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W) != 0) goto err;
  if (pvmmap(pgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X) != 0)              goto err;
    
  // map kernel stacks
  uint64 va, pa;
  for(int i=0; i<NPROC; i++) {
    va = KSTACK(i);
    pa = PTE2PA(*(walk(kernel_pagetable, va, 0)));
    if (pvmmap(pgtbl, va, pa, PGSIZE, PTE_R | PTE_W) != 0) {
      goto err;
    }
  }
  
  return pgtbl;

  err:
    pvm_destroy(pgtbl);
    return 0;
}

void 
pvm_destroy(pagetable_t pgtbl) {
  pvmunmap(pgtbl, 0, PLIC/PGSIZE);
  pvmunmap(pgtbl, KSTACK(NPROC-1), 2*NPROC);
  pvmunmap(pgtbl, TRAMPOLINE, PGSIZE/PGSIZE);
  pvmunmap(pgtbl, (uint64)etext, (PHYSTOP-(uint64)etext)/PGSIZE);
  pvmunmap(pgtbl, KERNBASE, ((uint64)etext-KERNBASE)/PGSIZE);
  pvmunmap(pgtbl, PLIC, 0x400000/PGSIZE);
  pvmunmap(pgtbl, VIRTIO0, PGSIZE/PGSIZE);
  pvmunmap(pgtbl, UART0, PGSIZE/PGSIZE);
  // vmprint(pgtbl);
  freewalk(pgtbl);
}


// Initialize the one kernel_pagetable
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch h/w page table register to the kernel's page table,
// and enable paging.
void
kvminithart()
{
  w_satp(MAKE_SATP(kernel_pagetable));
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  // printf("[walkaddr] pte=%p, *pte=%p\n", pte, *pte);
  pa = PTE2PA(*pte);
  // printf("[walkaddr] pa=%p\n", pa);
  return pa;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}


// add a mapping to the private kernel page table
// Returns 0 on success, -1 if cannot alloc new level-x pagetable.
int
pvmmap(pagetable_t pgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(pgtbl, va, sz, pa, perm) != 0)
    return -1;
  return 0;
}


// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned. Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if(size == 0)
    panic("mappages: size");
  
  a = PGROUNDDOWN(va);
  last = PGROUNDDOWN(va + size - 1);
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0){
      // printf("[mappages] walk error, va=%p, pte=%p, *pte=%p\n", a, pte, *pte);
      return -1;
    }
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. The mappings must exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0)
      panic("uvmunmap: walk");
    if((*pte & PTE_V) == 0)
      panic("uvmunmap: not mapped");
    if(PTE_FLAGS(*pte) == PTE_V)
      panic("uvmunmap: not a leaf");
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

// Remove npages of mappings starting from va. 
// va must be page-aligned. 
// The mappings MAY exist.
// WILL NOT free the physical memory.
void
pvmunmap(pagetable_t pagetable, uint64 va, uint64 npages)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("pvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0)
      continue;
    if((*pte & PTE_V) == 0)
      continue;
    if(PTE_FLAGS(*pte) == PTE_V)
      continue;
    
    *pte = 0;
  }
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Load the user initcode into address 0 of pagetable,
// for the very first process.
// sz must be less than a page.
void
uvminit(pagetable_t pagetable, uchar *src, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pagetable, 0, PGSIZE, (uint64)mem, PTE_W|PTE_R|PTE_X|PTE_U);
  memmove(mem, src, sz);
}

// Allocate PTEs and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    // printf("[uvmalloc] alloc va=%p @ pa=%p\n", a, mem);
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_W|PTE_X|PTE_R|PTE_U) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

uint64
pvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    pvmunmap(pagetable, PGROUNDUP(newsz), npages);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      vmprint(pagetable);
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & PTE_V) == 0)
      panic("uvmcopy: page not present");
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// Copy a pagetable without alloc PA. 
// returns 0 on success, -1 on failure.
int
pvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  // printf("[pvmcopy] size=%d\n", sz);
  pte_t *pte;
  uint64 pa, i;
  uint flags;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0){
      // printf("uvmcopy_pvt: pte should exist. va=%p\n", i);
      return -1;
    }

    if((*pte & PTE_V) == 0){
      continue;
    }

    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if (flags & PTE_U){
      flags = flags & (~PTE_U);
    }
    // printf("[pvmcopy] old flags=%p, new flags=%p\n", PTE_FLAGS(*pte), flags);
    // printf("[pvmcopy] i(va)=%p, pa=%p\n", i, pa);
    if(mappages(new, i, PGSIZE, pa, flags) != 0){
      return -1;
    }
  }
  return 0;

}

int
pvmalloc(pagetable_t upgtbl, pagetable_t ppgtbl, uint64 oldsz, uint64 newsz)
{
  uint64 pa, a;
  pte_t *pte;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    pte = walk(upgtbl, a, 0);
    if (pte == 0) {
      pvmdealloc(ppgtbl, a, oldsz);
      return 0;
    }

    pa = PTE2PA(*pte);
    // printf("[pvmalloc] map va=%p @ pa=%p\n", a, pa);
    if(pa == 0){
      pvmdealloc(ppgtbl, a, oldsz);
      return 0;
    }

    if(mappages(ppgtbl, a, PGSIZE, pa, PTE_W|PTE_X|PTE_R) != 0){
      pvmdealloc(ppgtbl, a, oldsz);
      return 0;
    }
  }
  return newsz;
}



// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  struct proc *p = myproc();
  (void)p;
  (void)pagetable;
  // 1. 边界与安全检查：
  // - srcva + len < srcva : 防止 64 位加法溢出（Wrap-around 攻击）
  // - srcva >= p->sz      : 起始虚拟地址越界
  // - srcva + len > p->sz  : 拷贝结束位置超出了当前进程申请的内存上限
  if (srcva + len < srcva || srcva >= p->sz || srcva + len > p->sz)
    return -1;

  // pte_t *pte = walk(p->pvt_kpgtbl, srcva, 0);
  // if (pte == 0) {
  //     printf("copyin Fault: VA 0x%x 在 pvt_kpgtbl 中根本没有建立映射!\n", srcva);
  // } else if ((*pte & PTE_V) == 0) {
  //     printf("copyin Fault: VA 0x%x 对应的 PTE_V 无效!\n", srcva);
  // } else if (*pte & PTE_U) {
  //     printf("copyin Fault: VA 0x%x 对应的 PTE 仍带有 PTE_U 标志位! (PTE 值为 0x%x)\n", srcva, *pte);
  // }
  

  // // 2. 内存拷贝：
  // // 此时当前 CPU 的 satp 寄存器指向 p->pvt_kpgtbl（没有 PTE_U 标志位），
  // // 硬件 MMU 会自动将 srcva 映射为物理地址，直接使用 memmove 即可。
  memmove(dst, (void *)srcva, len);

  return 0;


  // uint64 n, va0, pa0;
  // pte_t *pte_user, *pte_pvtk;
  // uint64 pa_user, pa_pvtk, flg_user, flg_pvtk;
  
  // while(len > 0){
  //   va0 = PGROUNDDOWN(srcva);
  //   if (va0 >= MAXVA) return -1;

  //   pte_user = walk(p->pagetable, va0, 0);
  //   pte_pvtk = walk(p->pvt_kpgtbl, va0, 0);
    

  //   if ((pte_user==0 && pte_pvtk) || (pte_user && pte_pvtk==0)) {
  //     printf("[copyin][PTE DISAGREE][va=%p] pte_user=%p, pte_pvtk=%p\n", va0, pte_user, pte_pvtk);
  //     return -1;
  //   }

  //   pa_user = PTE2PA(*pte_user); pa_pvtk = PTE2PA(*pte_pvtk);
  //   if ((pa_user==0 && pa_pvtk) || (pa_user && pa_pvtk==0)) {
  //     printf("[copyin][PTE2PA DISAGREE][va=%p] pa_user=%p, pa_pvtk=%p\n", va0, PTE2PA(*pte_user), PTE2PA(*pte_pvtk));
  //   }

  //   flg_user = PTE_FLAGS(*pte_user); flg_pvtk = PTE_FLAGS(*pte_pvtk);
  //   if ((flg_user&0x1F) != ((flg_pvtk & 0x1F) | PTE_U)) {
  //     printf("[copyin][PTE_FLAGS DISAGREE][va=%p] flg_user=%p, flg_pvtk=%p\n",  va0, flg_user, flg_pvtk);
  //   }
  //   if (flg_pvtk & PTE_U) {
  //     printf("[copyin][PTE_FLAGS has U in pvtk] flg_pvtk=%p\n", flg_pvtk);
  //   }

  //   pa0 = walkaddr(pagetable, va0);
  //   if(pa0 == 0)
  //     return -1;
  //   pa0 = pa_pvtk;
  //   n = PGSIZE - (srcva - va0);
  //   if(n > len)
  //     n = len;
  //   memmove(dst, (void *)(pa0 + (srcva - va0)), n);

  //   len -= n;
  //   dst += n;
  //   srcva = va0 + PGSIZE;
  // }
  // return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  struct proc *p = myproc();
  if (srcva >= p->sz || (uint64)dst >= MAXVA) {
    return -1;
  }
  
  (void)pagetable;
  uint64 n = max;
  char tmp;
  while (n > 0) {
    if (srcva >= p->sz) {
      return -1;
    }
    tmp = *(char *)srcva;
    if (tmp == '\0') {
      break;
    }
    *dst = *(char *)srcva;
    n--;
    dst++;
    srcva++;
    if (srcva >= p->sz || (uint64)dst >= MAXVA) {
      return -1;
    }
  }

  if (n==0) return -1;
  if (*(char *)srcva == '\0') {
    *dst = '\0';
  }
  return 0;
}

// print pagetable
void
vmprint(pagetable_t pagetable) 
{
  printf("page table %p\n", pagetable);
  vmprint_rec(pagetable, 2);
}

void vmprint_rec(pagetable_t pagetable, int level)
{
  pte_t pte;
  for(int i=0; i<512; i++) {
    pte = pagetable[i];
    
    // jump over invalid PTE
    if ((pte & PTE_V)==0) continue;

    // level>0  &&  not-leaf, panic
    if (level>0 && ((pte & (PTE_R|PTE_W|PTE_X)) > 0)) 
      panic("print page table");

    // print
    for (int j=0; j<(3-level); j++) printf(" ..");
    printf("%d: pte %p pa %p\n", i, pte, PTE2PA(pte));

    // descend if non-leaf

    if (level > 0) {
      vmprint_rec((pagetable_t)PTE2PA(pte), level-1);
    }

  }

}

void 
vmprint_page0(pagetable_t pagetable, char *desc) 
{ 
  printf("page table %p, %s\n", pagetable, desc);
  vmprint_rec_limit((pagetable_t)PTE2PA(pagetable[0]), 1, 96);
}

void vmprint_rec_limit(pagetable_t pagetable, int level, int cnt)
{
  pte_t pte;
  for(int i=0; i<cnt; i++) {
    pte = pagetable[i];
    
    // jump over invalid PTE
    if ((pte & PTE_V)==0) continue;

    // level>0  &&  not-leaf, panic
    if (level>0 && ((pte & (PTE_R|PTE_W|PTE_X)) > 0)) 
      panic("print page table");

    // print
    for (int j=0; j<(3-level); j++) printf(" ..");
    printf("%d: pte %p pa %p\n", i, pte, PTE2PA(pte));

    // descend if non-leaf

    if (level > 0) {
      vmprint_rec_limit((pagetable_t)PTE2PA(pte), level-1, 512);
    }

  }

}