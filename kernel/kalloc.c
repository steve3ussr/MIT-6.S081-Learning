// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;

struct spinlock page_refcnt_lock;
char page_refcnt[(PHYSTOP-KERNBASE)/PGSIZE];

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  initlock(&page_refcnt_lock, "page_refcnt_lock");
  set_page_refcnt((void *)KERNBASE, (void*)PHYSTOP, 1);
  freerange(end, (void*)PHYSTOP);
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  r = (struct run*)pa;

  acquire(&page_refcnt_lock);
    int refcnt_index = ((uint64)pa-KERNBASE)/PGSIZE;
    if (page_refcnt[refcnt_index] == 0) {
      printf("ERROR: kfree try to free a freed PA. \n");
      panic("kfree-refcnt-eq0");
    }

    page_refcnt[refcnt_index] -= 1;
    if (page_refcnt[refcnt_index] == 0) {
      memset(pa, 1, PGSIZE);  // Fill with junk to catch dangling refs.
      acquire(&kmem.lock);
        r->next = kmem.freelist;
        kmem.freelist = r;
      release(&kmem.lock);
    }
  release(&page_refcnt_lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
    kmem.freelist = r->next;
  release(&kmem.lock);

  if(r){
    memset((char*)r, 5, PGSIZE); // fill with junk

    acquire(&page_refcnt_lock);
      int page_refcnt_index = ((uint64)r-KERNBASE)/PGSIZE;
      if (page_refcnt[page_refcnt_index] != 0){
        printf("ERROR: kalloc new PA page (%p), but page refrcnt = %d\n", r, page_refcnt[page_refcnt_index]);
        debug_show_page_refcnt("error-kalloc-refcnt=0");
        panic("kalloc(refcnt)");
      }
      page_refcnt[page_refcnt_index] = 1;
    release(&page_refcnt_lock);
  }
  return (void*)r;
}

void
debug_show_page_refcnt(char *desc) {
  acquire(&page_refcnt_lock);
  printf("\n========== PAGE REFCNT: %s ==========\n", desc);
  printf("+-----------------------------\n|\n");
  int cnt_line;
  
  int page_per_line = 8;  // make sure page = 32K!
  int lines = 32*1024/page_per_line;
  
  for(int i=0; i<lines; i++) {
    cnt_line = 0;
    for(int j=0; j<page_per_line; j++){
      cnt_line += page_refcnt[page_per_line*i+j];
    }

    if (cnt_line == 0) {
      continue;
    }

    printf("| [%d-%d]\t%p - %p: ", i, cnt_line, KERNBASE+i*page_per_line*PGSIZE, KERNBASE+(i+1)*page_per_line*PGSIZE);
    for(int j=0; j<page_per_line; j++){

      printf("%d ", page_refcnt[page_per_line*i+j]);
    }
    printf("\n");
  }
  
  printf("|\n--------------------------------\n\n");
  release(&page_refcnt_lock);
}

// set refcnt on close-end
// cnt should <= NPROC (64)
void            
set_page_refcnt(void* start, void* end, int cnt)
{
  acquire(&page_refcnt_lock);

  int i = (PGROUNDDOWN((uint64)start) - KERNBASE)/PGSIZE;
  int i_max = (PGROUNDUP((uint64)end) - KERNBASE)/PGSIZE;
  
  for(; i<=i_max; i++) {
    page_refcnt[i] = cnt;
  }
  
  release(&page_refcnt_lock);
}
