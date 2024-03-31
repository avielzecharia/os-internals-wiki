# Linux #

## Tools ## 
* strace, ltrace
* ptrace (syscall hooking, code injection, debugging, etc.)
* gdb
  
## Random ##
* LD_PRELOAD (RTLD_NEXT)
* LSM hooks
* eBPF [only on boot]
* ELF format (GOT, PLT, PIE, RELO)
* seliux, setenforce binary
* syscall - int 0x80 (with stable syscall code)
* capabilities (per thread for uid=0)
* kernel modules
* exec VS execve
* IPC (pipes, sockets, shared memory, signals)
* /proc (and Virtual FS in general)
* LKRG – Linux Kernel Runtime Guard
* /dev/null
* Magisk
* common data structures: inode, super_block, module_list, task_struct, cred
* common syscalls: open, write, read, stat, ptrace, insmod, execve, fork, mount (int 0x80)

## Blogs ##
* https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist