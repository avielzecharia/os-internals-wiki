# Android #

## Tools ##
* useful binaries: dumpsys, logcat, adb, am ,content
* Frida, Xposed
  
## Buzzwords ##
* ARM architecture, Trustzone
  * https://azeria-labs.com
* eBPF usage on boot
* system server + ServiceManager [getSystemService]
* Binder internals (driver + serialization + stub etc.)
* Dex + DVM + Dalvik -> ART + AOT (dex2oat, etc.)
  * https://www.blackhat.com/docs/asia-15/materials/asia-15-Sabanal-Hiding-Behind-ART.pdf
* lifetime of APK from google store to execution (precompile all is slow VS runtime is important)
* Trustzone
* selinux
* fs-verity (Merkle tree), dm-verity
* GKI, open source kernel distributions
* APEX + ART dynamic updating
* Shared Preferences
* GMS, safetynet, droidguard
  * https://www.blackhat.com/docs/eu-17/materials/eu-17-Mulliner-Inside-Androids-SafetyNet-Attestation.pdf
  * https://www.romainthomas.fr/publication/22-sstic-blackhat-droidguard-safetynet/
* Android manifest, JNI + .so, classes.dex, assets VS resources [use JEB/JADX]
* Common processes: zygote, init, netd, vold, logd, installd (daemon as a concept)


## Blogs ##
* https://koz.io/
* https://github.com/user1342/Awesome-Android-Reverse-Engineering?tab=readme-ov-file
* https://github.com/shivsahni/The-Grey-Matter-of-Securing-Android-Applications
