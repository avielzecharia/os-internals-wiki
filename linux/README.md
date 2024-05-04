# Linux #

## Tools ## 
* strace, ltrace
* ptrace (syscall hooking, code injection, debugging, etc.)
* gdb
  
## Buzzwords ##
* LD_PRELOAD (RTLD_NEXT)
* LSM hooks
* eBPF
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
* Common data structures: inode, super_block, module_list, task_struct, cred
* Common syscalls: open, write, read, stat, ptrace, insmod, execve, fork, mount (int 0x80)

## Blogs ##
* https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
* https://fareedfauzi.github.io/2024/03/29/Linux-Forensics-cheatsheet.html