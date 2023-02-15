# Introduction
- IrfanView is a fast, compact and innovative FREEWARE (for non-commercial use) graphic viewer for Windows XP, Vista, 7, 8, 10 and 11.
- Official site: [https://www.irfanview.com/](https://www.fosshub.com/IrfanView.html)

# Infected Components
- Irfanview 4.62 - 32 bit with Irfanview plugins 4.62 - 32 bit, which can be found in [https://www.fosshub.com/IrfanView.html](https://www.fosshub.com/IrfanView.html) or just download in this repository
- JEPG2000.dll version 4.56.0.0 in `"C:\Program Files (x86)\IrfanView\Plugins"`

# Vulnerability Description
Irfanview v4.62 allows a user-mode write access violation via a crafted JPEG 2000 file starting at `JPEG2000+0x0000000000001bf0`.

# PoC
- Open `i_view32.exe`, using WinDbg and attach to this process.
- Open the crafted file `id_000004_00_STATUS_HEAP_CORRUPTION.jp2` then tirgger an Access Violation fault.
- WinDbg record can be seen like this

```shell
0:004> g
(2570.2488): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files (x86)\IrfanView462\Plugins\JPEG2000.DLL
eax=00000000 ebx=00000001 ecx=00000003 edx=00000000 esi=056fd000 edi=0bd9ed70
eip=72ac1bf0 esp=00197bf0 ebp=00197c24 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
JPEG2000+0x1bf0:
72ac1bf0 8806            mov     byte ptr [esi],al          ds:002b:056fd000=??
0:000> kv
 # ChildEBP RetAddr      Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00 00197c24 72af125d     0bd9ed50 00000000 00000000 JPEG2000+0x1bf0
01 00197c58 72af1139     0505eda0 0bd9ed50 00000020 JPEG2000!ShowPlugInSaveOptions_W+0x2c75d
02 00197cac 72aef1ac     0505eda0 056d8f38 078b2e40 JPEG2000!ShowPlugInSaveOptions_W+0x2c639
03 00197ce0 72ae1d47     0bdb0fe8 00000000 00000020 JPEG2000!ShowPlugInSaveOptions_W+0x2a6ac
04 00197d10 72acb857     00000000 00000000 00000010 JPEG2000!ShowPlugInSaveOptions_W+0x1d247
05 00197d2c 72acb6a6     0505eda0 00000000 00000020 JPEG2000!ShowPlugInSaveOptions_W+0x6d57
06 00197d58 72ac39be     0505eda0 00197e96 00198118 JPEG2000!ShowPlugInSaveOptions_W+0x6ba6
07 00197e54 004338fc     005b13c0 00000000 00198118 JPEG2000!ReadJPG2000_W+0xbfe
08 00198e84 7694ac1f     00198ea4 76ad5d5b 00198eb4 i_view32+0x338fc
09 00198eb4 7694b733     00199148 00000001 00199174 msvcrt!write_string+0x3a (FPO: [Non-Fpo])
0a 00199154 00199270     00000001 749aae41 03fa00e8 msvcrt!_output_l+0xae3 (FPO: [Non-Fpo])
0b 0019919c 76e210ec     d6fe2c99 00199154 0000c018 0x199270
0c 001991c0 749aaefb     0000104b 00000000 00199458 win32u!NtUserGetProp+0xc (FPO: [2,0,0])
0d 00000000 00000000     00000000 00000000 00000000 COMCTL32!CallNextSubclassProc+0x1bb (FPO: [Non-Fpo])
0:000> u
JPEG2000+0x1bf0:
72ac1bf0 8806            mov     byte ptr [esi],al
72ac1bf2 03751c          add     esi,dword ptr [ebp+1Ch]
72ac1bf5 83eb01          sub     ebx,1
72ac1bf8 75e6            jne     JPEG2000+0x1be0 (72ac1be0)
72ac1bfa 5f              pop     edi
72ac1bfb 5e              pop     esi
72ac1bfc 33c0            xor     eax,eax
72ac1bfe 5b              pop     ebx
0:000> db [esi-20]
056fcfe0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
056fcff0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
056fd000  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
056fd010  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
056fd020  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
056fd030  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
056fd040  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
056fd050  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
```
- As we can see, in this circle `esi` is always add a common number in stack, and then `mov     byte ptr [esi],al` command assigns value from `eax` low bits to the memory where `esi` points to. 
- ![](jepg2000+1bf0.png)
- ![](pseudo code.png)
- Using x32dbg for verification, `v9=ebx=0x20, v18=esi= 0x0F006FC2, v64=[ebp+1C]=0x2`, in each circle, `v18+=2, v9-=1`, so finally `esi =0x0F006FC2+0x2*0x20=0xF007002`, but the memory buffer malloced ends at 0x0F006FFF < 0xF007002, causing the access violation.
- ![](x32dbg.png)

# Impact 
Denial of Service
