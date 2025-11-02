#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"

// kernel/syscall.c
static char *syscall_names[] = {
  [SYS_fork]   "fork",
  [SYS_exit]   "exit",
  [SYS_wait]   "wait",
  [SYS_pipe]   "pipe",
  [SYS_read]   "read",
  [SYS_kill]   "kill",
  [SYS_exec]   "exec",
  [SYS_fstat]  "fstat",
  [SYS_chdir]  "chdir",
  [SYS_dup]    "dup",
  [SYS_getpid] "getpid",
  [SYS_sbrk]   "sbrk",
  [SYS_sleep]  "sleep",
  [SYS_uptime] "uptime",
  [SYS_open]   "open",
  [SYS_write]  "write",
  [SYS_mknod]  "mknod",
  [SYS_unlink] "unlink",
  [SYS_link]   "link",
  [SYS_mkdir]  "mkdir",
  [SYS_close]  "close",
  [SYS_trace]  "trace",
};


// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz) // both tests needed, in case of overflow
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
  if(copyinstr(p->pagetable, buf, addr, max) < 0)
    return -1;
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
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);
extern uint64 sys_trace(void);

// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
[SYS_trace]   sys_trace,
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
};



void
syscall(void)
{
  struct proc *p = myproc();
  int num = p->trapframe->a7;

  if(num > 0 && num < NELEM(syscalls) && syscalls[num]){
    // 先存原始參數，避免之後被覆蓋
    uint64 a0 = p->trapframe->a0;   // path（給 exec/open 等）
    uint64 a1 = p->trapframe->a1;   // argv（給 exec）

    // 專給 exec 用：先把 argv[0] 取出來，因為待會兒 exec 可能換位址空間
    int traced_before;
    acquire(&p->lock);
    traced_before = p->traced;
    release(&p->lock);

    int have_prog = 0;          // 是否成功取到 argv[0]
    char prog[128];             // 先把要印的程式名存起來
    if(traced_before && num == SYS_exec){
      uint64 uargv = a1;        // a1 = argv 的使用者位址 (char**)
      uint64 uargv0;
      if(uargv != 0 && fetchaddr(uargv, &uargv0) >= 0 && uargv0 != 0){
        if(fetchstr(uargv0, prog, sizeof(prog)) >= 0){
          have_prog = 1;
        }
      }
    }

    // 執行真正的系統呼叫
    uint64 ret = syscalls[num]();
    p->trapframe->a0 = ret;

    // 呼叫後再判斷是否要印（避免競態，簡單地再讀一次）
    int traced;
    acquire(&p->lock);
    traced = p->traced;
    release(&p->lock);

    if(traced){
      char *name = "unknown";
      if(num >= 0 && num < NELEM(syscall_names) && syscall_names[num])
        name = syscall_names[num];

      if(num == SYS_open || num == SYS_unlink || num == SYS_chdir ||
         num == SYS_mkdir || num == SYS_link){
        char s[128];
        if(fetchstr(a0, s, sizeof(s)) < 0)
          printf("[pid %d] %s(<bad ptr>) = %d\n", p->pid, name, (int)ret);
        else
          printf("[pid %d] %s(\"%s\") = %d\n", p->pid, name, s, (int)ret);

      } else if(num == SYS_exec){
        if(have_prog)
          printf("[pid %d] exec(\"%s\") = %d\n", p->pid, prog, (int)ret);
        else
          printf("[pid %d] exec(<bad ptr>) = %d\n", p->pid, (int)ret);

      } else {
        printf("[pid %d] %s(%d) = %d\n", p->pid, name, (int)a0, (int)ret);
      }
    }

  } else {
    printf("%d %s: unknown sys call %d\n", p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
