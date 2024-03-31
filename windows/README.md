# Windows #

## Tools ##
* SysInternals - ProcExp,VMMap, ProcMon, WinObj, TcpView, livekd, WinObj, RAMMap, PoolMap
* RPCViewer
* Dependency Walker 
* BurpSuite, WireShark
* rundll, sc, bcdedit
* WinDbg, TTD
  * https://github.com/yardenshafir/WinDbg_Scripts
* IDA
* CFF Explorer

## Random ##
* Smart App Control (SAP) + Windows defender Application Control (WDAC)
  * https://n4r1b.com/posts/2022/08/smart-app-control-internals-part-1/
* ELAM - Early Launch Anti Malware [special boot registry hive]
  * https://n4r1b.com/posts/2019/11/understanding-wdboot-windows-defender-elam/
* IRQL - Interrupt Request Level, ISR - Interrupt Service Routine
  * https://github.com/RixedLabs/Community-Papers/blob/master/Windows-Irqls/Windows%20Irqls.pdf
* WOW64
  * syscall wow64cpu->eoe64win->wow64, filesystem system32->syswow64, registry ->wow6432node
* PTE (NXbit, COW), PFN, VAD, SLAT
  * 
* PPL - Protected Process Light
  * https://itm4n.github.io/lsass-runasppl/
* win32k
* PE format (IAT, EAT, RVA, sections, directories)
* windows SmartScreen
* TPM - Trusted Platform Module (TCG Log)
* MiniFilters - fltmc, !fltkd, FltMgr.sys, FltRegisterFilter syscall
  * https://www.osr.com/nt-insider/2019-issue1/the-state-of-windows-file-system-filtering-in-2019/
* Access Token, Permissions (DACL), UAC
  * https://www.elastic.co/blog/introduction-to-windows-tokens-for-security-practitioners
* Registry Callback (cm)
* ETW - Event Tracing for Windows [Microsoft-Windows-Threat-Intelligence]
  * https://blog.trailofbits.com/2023/11/22/etw-internals-for-security-research-and-forensics/
* UMCI - Code Integrity
  * https://www.cybereason.com/blog/code-integrity-in-the-kernel-a-look-into-cidll
* VBS - Virtualization Based Security [VTL, truslet, SecureKernel, root partition]
* Process Injection
  * https://github.com/PolariumLabs/al-khaser/tree/master/al-khaser/Code%20Injections
* PatchGuard & HyperGuard
* MDL - Memory Descriptor List
  * https://www.osronline.com/article.cfm%5Eid=423.htm
* DR - Debug registers, CR - Control registers, MSR - Model Specific Registers
* IPC, LPC, ALPC, RPC - Inter/Local/Remote Procedure Call
* Access Token, Security Descriptor, User & Groups, UAC
* WFP - Windows Filtering Platform [netsh wfp show filters], NDIS - Network Driver Interface Specification
  * https://n4r1b.com/posts/2020/01/dissecting-the-windows-defender-driver-wdfilter-part-1/
* Object Manager Callbacks (PsSet)
* WNF - Windows Notification Facility
  * https://www.youtube.com/watch?v=MybmgE95weo
  * https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html
* AMSI - Anti Malware Scan Interface
  * https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf
* COM - Component Object Model [Distributed, IDL]
  * https://www.codeproject.com/Articles/13601/COM-in-plain-C


## Protocols ##
* NTLM (Domain Controller)
  * https://csandker.io/2017/09/10/NTLMAuthenticationAWrapUp.html
* Kerberos
  * https://twitter.com/Kostastsale/status/1711656782802874728
  * https://csandker.io/2017/09/12/KerberosAuthenticationAWrapUp.html

## Blogs ##
* Malware Analysis
  * https://github.com/RPISEC/Malware?tab=readme-ov-file
  * https://github.com/benoitsevens/applying-ttd-to-malware-analysis/tree/master
* Red Team
  * https://www.ired.team/
* https://rayanfam.com/
* https://www.alex-ionescu.com/
* https://empyreal96.github.io/nt-info-depot/WinBooks.html
* https://itm4n.github.io/
* https://n4r1b.com/
* https://csandker.io/
* https://windows-internals.com/pages/internals-blog/